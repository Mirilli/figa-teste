'use strict';

const express = require('express');
const db      = require('../database');
const router  = express.Router();

// GET /api/sections — retorna seções ativas ordenadas (público)
router.get('/', (req, res) => {
  const sections = db.prepare(`
    SELECT id, type, label, position, content
    FROM site_sections
    WHERE active = 1
    ORDER BY position ASC
  `).all();

  return res.json(sections.map(s => ({
    ...s,
    content: JSON.parse(s.content || '{}'),
  })));
});

module.exports = router;
