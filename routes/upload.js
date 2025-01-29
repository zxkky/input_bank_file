const express = require('express');
const db = require('../config/database');

const router = express.Router();

router.post('/upload', (req, res) => {
    const { file_number, date, loan_amount, borrower_name, marketing, rek } = req.body;

    const sql = "INSERT INTO bank_files (file_number, date, loan_amount, borrower_name, marketing,  rek) VALUES (?, ?, ?, ?, ?, ?)";
    db.query(sql, [file_number, date, loan_amount, borrower_name, marketing, rek], (err, result) => {
        if (err) throw err;
        res.send('Data saved successfully!');
    });
});
router.get('/files', (req, res) => {
    const sql = "SELECT * FROM bank_files";
    db.query(sql, (err, results) => {
        if (err) throw err;
        res.render('files', { files: results });
    });
});


module.exports = router;