"""
AML·CDD Risk Screening API — Supabase Backend v3.0
====================================================
Framework  : FastAPI
Database   : Supabase (PostgreSQL via supabase-py)
Auth       : API Key (header: X-API-Key)
Matching   : Exact + fuzzy (pg_trgm) with confidence score

Install:
  pip install fastapi uvicorn httpx supabase python-dotenv

Run locally:
  uvicorn main:app --reload --port 8000

Environment variables (.env):
  API_KEY=your-secret-api-key
  SUPABASE_URL=https://xxxx.supabase.co
  SUPABASE_SERVICE_KEY=your-service-role-key
  PORT=8000
"""

import os, hashlib, time, asyncio
from datetime import datetime, timezone
from typing import Optional, List
import httpx
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL         = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase: Client     = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

app = FastAPI(title="AML·CDD Supabase API", version="3.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST","GET","PUT","DELETE"], allow_headers=["*"])

API_KEY        = os.getenv("API_KEY", "aml-dev-key-change-in-production")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(key: str = Security(api_key_header)):
    if key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return key

MAS_LIST = ["AL QAEDA","JEMAAH ISLAMIYAH","ABU SAYYAF","HEZBOLLAH","HAMAS","ISLAMIC STATE","ISIS","DAESH","FARC","LASHKAR E TAYYIBA","HAQQANI NETWORK","AL SHABAAB","BOKO HARAM","AL NUSRA"]
HIGH_RISK_COUNTRIES = ["Myanmar","Cambodia","Iran","North Korea","Russia","Syria","Other High-Risk Country"]
MED_RISK_COUNTRIES  = ["Indonesia","Vietnam","Philippines","China"]
HIGH_RISK_OCC       = ["Gambling / Casino","Cryptocurrency / Digital Assets","Precious Metals / Stones"]
MED_RISK_OCC        = ["Legal / Law","Real Estate","Import / Export"]
HIGH_RISK_BIZ       = ["Cryptocurrency / Digital Assets","Legal / Professional Services"]
MED_RISK_BIZ        = ["Real Estate","Import / Export / Trading","Financial Services"]

class ScreeningRequest(BaseModel):
    name: str
    entity_type: str = "INDIVIDUAL"
    nationality: str = "Singapore"
    occupation: str = "Other"
    dob: Optional[str] = None
    id_number: Optional[str] = None
    address: Optional[str] = None
    source_of_funds: str = "Employment Income"
    source_of_wealth: str = "Salary / Wages"
    income_bracket: str = "$30,000 - $100,000"
    transaction_volume: str = "Low (< $50K/yr)"
    pep_status: int = 0
    pep_jurisdiction: Optional[str] = None
    adverse_media: int = 0
    prior_sar: int = 0
    business_name: Optional[str] = None
    business_reg: Optional[str] = None
    business_role: str = "No Formal Role"
    business_industry: str = "Other"
    related_entities: Optional[str] = None
    notes: Optional[str] = None

class WatchlistEntry(BaseModel):
    entity_type: str
    full_name: str
    risk_tier: str
    id_number: Optional[str] = None
    nationality: Optional[str] = None
    reason_codes: List[str] = []
    reason_text: Optional[str] = None
    source: str = "Internal"
    case_reference: Optional[str] = None
    notes: Optional[str] = None
    aliases: List[str] = []
    linked_entities: List[dict] = []

class Flag(BaseModel):
    level: str
    message: str
    rule: str

class DBMatch(BaseModel):
    entity_id: str
    full_name: str
    entity_type: str
    risk_tier: str
    reason_codes: List[str]
    reason_text: Optional[str]
    source: str
    id_number: Optional[str]
    nationality: Optional[str]
    match_source: str
    matched_value: str
    similarity: float
    confidence: str
    is_exact: bool

class ScreeningResponse(BaseModel):
    profile_id: str
    name: str
    risk_score: int
    risk_level: str
    cdd_recommendation: str
    screened_at: str
    flags: List[Flag]
    db_matches: List[DBMatch]
    sanctions_hits: List[dict]
    db_match_count: int
    confirmed_hit_count: int
    sanctions_clear: bool
    pep_detected: bool
    requires_edd: bool
    requires_str: bool
    sources_checked: List[str]
    processing_ms: int

def dice_similarity(a: str, b: str) -> float:
    if not a or not b: return 0.0
    if a == b: return 1.0
    if a in b or b in a: return 0.85
    def bigrams(s): return set(s[i:i+2] for i in range(len(s)-1))
    ba, bb = bigrams(a), bigrams(b)
    if not ba or not bb: return 0.0
    return (2 * len(ba & bb)) / (len(ba) + len(bb))

async def query_supabase_watchlist(name: str, id_number: str = None) -> List[DBMatch]:
    matches = []
    try:
        resp = supabase.rpc("search_watchlist", {"p_name": name, "p_threshold": 0.25}).execute()
        for row in (resp.data or []):
            sim = float(row.get("similarity", 0))
            matches.append(DBMatch(
                entity_id=str(row["entity_id"]), full_name=row["full_name"],
                entity_type=row["entity_type"], risk_tier=row["risk_tier"],
                reason_codes=row.get("reason_codes") or [], reason_text=row.get("reason_text"),
                source=row.get("source","Internal"), id_number=row.get("id_number"),
                nationality=row.get("nationality"), match_source=row["match_source"],
                matched_value=row["matched_value"], similarity=round(sim,3),
                confidence="HIGH" if sim>=0.80 else "MEDIUM" if sim>=0.50 else "LOW",
                is_exact=sim>=0.95
            ))
        if id_number:
            id_resp = supabase.table("watchlist_entities").select("*").eq("id_number", id_number).eq("is_active", True).execute()
            existing = {m.entity_id for m in matches}
            for row in (id_resp.data or []):
                if str(row["id"]) not in existing:
                    matches.append(DBMatch(
                        entity_id=str(row["id"]), full_name=row["full_name"],
                        entity_type=row["entity_type"], risk_tier=row["risk_tier"],
                        reason_codes=row.get("reason_codes") or [], reason_text=row.get("reason_text"),
                        source=row.get("source","Internal"), id_number=row.get("id_number"),
                        nationality=row.get("nationality"), match_source="ID_NUMBER",
                        matched_value=id_number, similarity=1.0, confidence="HIGH", is_exact=True
                    ))
    except Exception as e:
        print(f"Supabase error: {e}")
    matches.sort(key=lambda m: m.similarity, reverse=True)
    return matches

async def query_sanctions_network(name: str) -> List[dict]:
    matches = []
    try:
        url = f"https://api.sanctions.network/rpc/search_sanctions?name={name}&limit=20"
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers={"Accept":"application/json"})
            if resp.status_code == 200:
                label_map = {"ofac":"OFAC SDN","unsc":"UN Security Council","eu":"EU Financial Sanctions File"}
                for item in (resp.json() or []):
                    sources = item.get("source") if isinstance(item.get("source"),list) else [item.get("source","")]
                    names   = item.get("names")   if isinstance(item.get("names"),list)   else [item.get("names","")]
                    matched = names[0] if names else "Unknown"
                    sim = dice_similarity(name.upper(), matched.upper())
                    for src in sources:
                        matches.append({"matched_name":matched,"source":src,"source_label":label_map.get(src,src.upper()),
                            "program":item.get("program"),"countries":item.get("countries",""),
                            "similarity":round(sim,3),"is_confirmed_hit":sim>0.65})
    except Exception as e:
        print(f"Sanctions API error: {e}")
    return matches

def check_mas_list(name: str) -> List[dict]:
    upper, hits = name.upper(), []
    for entry in MAS_LIST:
        sim = dice_similarity(upper, entry)
        if sim > 0.45 or any(w in upper for w in entry.split() if len(w)>4):
            hits.append({"matched_name":entry,"source":"mas","source_label":"MAS Designated Entities (SG)",
                "program":"MAS Counter-Terrorism Designation","countries":"Multiple",
                "similarity":round(sim,3),"is_confirmed_hit":sim>0.65})
    return hits

def calculate_risk(data: ScreeningRequest, db_matches: List[DBMatch], sanctions: List[dict]) -> tuple:
    score, flags = 0, []
    critical_db = [m for m in db_matches if m.risk_tier in ("CRITICAL","HIGH") and m.confidence in ("HIGH","MEDIUM")]
    medium_db   = [m for m in db_matches if m.risk_tier=="MEDIUM" and m.confidence in ("HIGH","MEDIUM")]
    if critical_db:
        score += 50
        reasons = list(set(rc for m in critical_db for rc in m.reason_codes))
        flags.append(Flag(level="critical",message=f"WATCHLIST HIT: {len(critical_db)} match(es) — {', '.join(reasons[:3])}",rule="DB_WATCHLIST_CRITICAL"))
    elif medium_db:
        score += 20
        flags.append(Flag(level="warning",message=f"Watchlist: {len(medium_db)} MEDIUM risk record(s) in internal database",rule="DB_WATCHLIST_MEDIUM"))
    if [m for m in db_matches if m not in critical_db and m not in medium_db]:
        score += 8
        flags.append(Flag(level="info",message="Partial watchlist match — low confidence, manual review recommended",rule="DB_WATCHLIST_LOW"))
    if data.nationality in HIGH_RISK_COUNTRIES:
        score+=30; flags.append(Flag(level="critical",message=f"High-risk jurisdiction: {data.nationality}",rule="JURISDICTION_HIGH"))
    elif data.nationality in MED_RISK_COUNTRIES:
        score+=12; flags.append(Flag(level="warning",message=f"Elevated-risk jurisdiction: {data.nationality}",rule="JURISDICTION_MED"))
    pep_pts=[0,30,18,14]; pep_labels=["","Current PEP","Former PEP","PEP Associate"]
    if data.pep_status>0:
        score+=pep_pts[data.pep_status]
        jur=f" ({data.pep_jurisdiction})" if data.pep_jurisdiction else ""
        flags.append(Flag(level="critical",message=f"PEP: {pep_labels[data.pep_status]}{jur}",rule="PEP_DETECTED"))
    adv_pts=[0,10,25,40]; adv_labels=["","Minor/unconfirmed","Confirmed adverse","Criminal charges"]
    if data.adverse_media>0:
        score+=adv_pts[data.adverse_media]
        flags.append(Flag(level="critical" if data.adverse_media>=2 else "warning",message=f"Adverse media: {adv_labels[data.adverse_media]}",rule="ADVERSE_MEDIA"))
    if data.prior_sar==2: score+=22; flags.append(Flag(level="critical",message="Prior STR/SAR at this institution",rule="PRIOR_STR_THIS"))
    elif data.prior_sar==1: score+=10; flags.append(Flag(level="warning",message="Prior STR/SAR at another institution",rule="PRIOR_STR_OTHER"))
    if data.occupation in HIGH_RISK_OCC: score+=15; flags.append(Flag(level="warning",message=f"High-risk occupation: {data.occupation}",rule="OCC_HIGH"))
    elif data.occupation in MED_RISK_OCC: score+=7; flags.append(Flag(level="info",message=f"Elevated occupation: {data.occupation}",rule="OCC_MED"))
    if data.business_industry in HIGH_RISK_BIZ: score+=12; flags.append(Flag(level="warning",message=f"High-risk sector: {data.business_industry}",rule="BIZ_HIGH"))
    elif data.business_industry in MED_RISK_BIZ: score+=6; flags.append(Flag(level="info",message=f"Elevated sector: {data.business_industry}",rule="BIZ_MED"))
    if data.source_of_funds=="Unknown" or "Unknown" in data.source_of_wealth:
        score+=15; flags.append(Flag(level="critical",message="Source of funds/wealth unknown",rule="SOF_UNKNOWN"))
    hi_txn="Very High" in data.transaction_volume or "High ($500K" in data.transaction_volume
    lo_inc="$30,000" in data.income_bracket or "< $30" in data.income_bracket
    if hi_txn and lo_inc: score+=22; flags.append(Flag(level="critical",message="Transaction volume inconsistent with income — possible structuring",rule="TXN_MISMATCH"))
    if data.business_role=="Nominee Director": score+=13; flags.append(Flag(level="warning",message="Nominee director — UBO verification required",rule="NOMINEE_DIR"))
    if data.related_entities and len(data.related_entities)>60: score+=8; flags.append(Flag(level="info",message="Complex corporate structure",rule="COMPLEX_STRUCT"))
    confirmed=[h for h in sanctions if h.get("is_confirmed_hit")]
    potential=[h for h in sanctions if not h.get("is_confirmed_hit")]
    if confirmed:
        score+=40; lists=[*set(h["source_label"] for h in confirmed)]
        flags.append(Flag(level="critical",message=f"SANCTIONS MATCH: {len(confirmed)} hit(s) on {', '.join(lists)}",rule="SANCTIONS_CONFIRMED"))
    elif potential:
        score+=15; flags.append(Flag(level="warning",message=f"Potential sanctions match — {len(potential)} result(s)",rule="SANCTIONS_POTENTIAL"))
    score=min(score,100)
    level="LOW" if score<35 else "MEDIUM" if score<65 else "HIGH"
    return score, level, flags

def log_screening(data, result, api_key, duration_ms):
    try:
        supabase.table("screening_log").insert({
            "screened_name":data.name,"entity_type":data.entity_type,
            "risk_score":result.risk_score,"risk_level":result.risk_level,
            "db_matches":result.db_match_count,"confirmed_hits":result.confirmed_hit_count,
            "analyst":"EDMUND KER","api_key_hash":hashlib.sha256(api_key.encode()).hexdigest()[:16],
            "duration_ms":duration_ms,
            "payload_summary":{"nationality":data.nationality,"pep_status":data.pep_status,"adverse_media":data.adverse_media}
        }).execute()
    except Exception as e:
        print(f"Log error: {e}")

@app.get("/health")
async def health():
    db_ok=False
    try: supabase.table("watchlist_entities").select("id").limit(1).execute(); db_ok=True
    except: pass
    return {"status":"online","version":"3.0.0","database":"connected" if db_ok else "error","timestamp":datetime.now(timezone.utc).isoformat()}

@app.post("/screen", response_model=ScreeningResponse)
async def screen_profile(data: ScreeningRequest, api_key: str = Depends(verify_api_key)):
    if not data.name or len(data.name.strip())<2:
        raise HTTPException(status_code=422, detail="Name required")
    t0=time.monotonic()
    db_matches,sanctions_hits,mas_hits = await asyncio.gather(
        query_supabase_watchlist(data.name, data.id_number),
        query_sanctions_network(data.name),
        asyncio.to_thread(check_mas_list, data.name)
    )
    all_sanctions=sanctions_hits+mas_hits
    score,level,flags=calculate_risk(data,db_matches,all_sanctions)
    confirmed_db=[m for m in db_matches if m.confidence in ("HIGH","MEDIUM") and m.risk_tier in ("HIGH","CRITICAL")]
    confirmed_sanc=[h for h in all_sanctions if h.get("is_confirmed_hit")]
    pep_detected=data.pep_status>0
    requires_edd=level=="HIGH" or (level=="MEDIUM" and (pep_detected or len(confirmed_db)>0))
    requires_str=bool(confirmed_sanc) or data.adverse_media==3
    rec_map={"LOW":"Standard CDD. Proceed with onboarding.","MEDIUM":"Enhanced scrutiny required. Senior sign-off needed.","HIGH":"HIGH RISK — Do NOT proceed. File STR. Full EDD required."}
    duration_ms=int((time.monotonic()-t0)*1000)
    profile_id=f"PRF-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{abs(hash(data.name))%10000:04d}"
    result=ScreeningResponse(
        profile_id=profile_id,name=data.name,risk_score=score,risk_level=level,
        cdd_recommendation=rec_map[level],screened_at=datetime.now(timezone.utc).isoformat(),
        flags=flags,db_matches=db_matches,sanctions_hits=all_sanctions,
        db_match_count=len(db_matches),confirmed_hit_count=len(confirmed_db)+len(confirmed_sanc),
        sanctions_clear=len(all_sanctions)==0,pep_detected=pep_detected,
        requires_edd=requires_edd,requires_str=requires_str,
        sources_checked=["Supabase Watchlist","OFAC SDN","UN SC","EU FSF","MAS"],
        processing_ms=duration_ms
    )
    asyncio.create_task(asyncio.to_thread(log_screening,data,result,api_key,duration_ms))
    return result

@app.get("/watchlist")
async def list_watchlist(limit:int=50,offset:int=0,risk_tier:str=None,entity_type:str=None,api_key:str=Depends(verify_api_key)):
    q=supabase.table("watchlist_entities").select("id,entity_type,full_name,risk_tier,reason_codes,source,nationality,is_active,listed_at").eq("is_active",True).order("listed_at",desc=True).range(offset,offset+limit-1)
    if risk_tier: q=q.eq("risk_tier",risk_tier)
    if entity_type: q=q.eq("entity_type",entity_type)
    resp=q.execute()
    return {"count":len(resp.data),"data":resp.data}

@app.post("/watchlist")
async def add_watchlist_entry(entry:WatchlistEntry,api_key:str=Depends(verify_api_key)):
    payload={k:v for k,v in entry.dict().items() if k not in ("aliases","linked_entities")}
    payload["listed_by"]="EDMUND KER"
    resp=supabase.table("watchlist_entities").insert(payload).execute()
    new_id=resp.data[0]["id"]
    if entry.aliases:
        supabase.table("watchlist_aliases").insert([{"entity_id":new_id,"alias":a,"alias_type":"AKA"} for a in entry.aliases if a.strip()]).execute()
    if entry.linked_entities:
        supabase.table("watchlist_linked_entities").insert([{"entity_id":new_id,**le} for le in entry.linked_entities]).execute()
    return {"status":"created","entity_id":new_id,"name":entry.full_name}

@app.delete("/watchlist/{entity_id}")
async def deactivate_entry(entity_id:str,api_key:str=Depends(verify_api_key)):
    supabase.table("watchlist_entities").update({"is_active":False}).eq("id",entity_id).execute()
    return {"status":"deactivated","entity_id":entity_id}

@app.get("/screening-log")
async def get_log(limit:int=100,api_key:str=Depends(verify_api_key)):
    resp=supabase.table("screening_log").select("*").order("screened_at",desc=True).limit(limit).execute()
    return {"count":len(resp.data),"data":resp.data}
