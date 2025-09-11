const express = require('express');
const router = express.Router();
const User = require('../models/User');
 // Import the User model

    // GET all users
    router.get('/', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
    });

    // POST create a new user
    router.post('/', async (req, res) => {
    try {
        const newUser = new User(req.body);
        await newUser.save();
        res.status(201).json(newUser);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
    });

    module.exports = router;
