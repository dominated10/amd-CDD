const express = require('express');
const app = express();
app.use(express.json());

const TARGET = 'https://aml-cdd-api-copy-copy-copy-copy-copy-copy-production.up.railway.app';
const API_KEY = process.env.API_KEY;

app.use((req, res) => {
  res.header('Access-Control-Allow-Origin', 'https://screen989.netlify.app');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE');
  if (req.method === 'OPTIONS') return res.sendStatus(200);

  fetch(`${TARGET}${req.url}`, {
    method: req.method,
    headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
    body: req.method !== 'GET' ? JSON.stringify(req.body) : undefined
  })
  .then(r => r.json())
  .then(d => res.json(d))
  .catch(e => res.status(500).json({ error: e.message }));
});

app.listen(process.env.PORT || 3000);