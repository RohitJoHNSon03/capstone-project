const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator');
const User = require('../models/User'); // Your Mongoose model
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// ========================== REGISTER ==========================
// @route   POST /api/auth/register
// @desc    Register user
router.post('/register', 
    [
        check('firstName', 'First name is required').not().isEmpty(),
        check('lastName', 'Last name is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('phone', 'Please include a valid phone number').isMobilePhone(),
        check('password', 'Password must be 8+ chars with uppercase, number, and special char')
            .matches(/^(?=.*\d)(?=.*[A-Z])(?=.*\W).{8,}$/),
        check('userType', 'User type is required').isIn(['buyer', 'seller'])
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                message: "Validation failed",
                errors: errors.array().reduce((acc, err) => {
                    acc[err.param] = { msg: err.msg };
                    return acc;
                }, {})
            });
        }

        const { firstName, lastName, email, phone, password, userType } = req.body;

        try {
            let user = await User.findOne({ email });
            if (user) {
                return res.status(409).json({ message: "Email already registered" });
            }

            user = await User.findOne({ phone });
            if (user) {
                return res.status(409).json({ message: "Phone number already registered" });
            }

            user = new User({
                firstName,
                lastName,
                email,
                phone,
                password,
                userType
            });

            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            await user.save();

            const payload = {
                user: {
                    id: user.id,
                    userType: user.userType
                }
            };

            jwt.sign(
                payload,
                process.env.JWT_SECRET,
                { expiresIn: '5d' },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token, userType: user.userType });
                }
            );
        } catch (err) {
            console.error(err.message);

            if (err.code === 11000) {
                const field = Object.keys(err.keyPattern)[0];
                return res.status(409).json({
                    message: `${field} already exists`
                });
            }

            res.status(500).json({ message: "Server error during registration" });
        }
    }
);

// ========================== LOGIN ==========================
// @route   POST /api/auth/login
// @desc    Authenticate user & get token
router.post('/login',
    [
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Password is required').exists()
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                message: "Validation failed",
                errors: errors.array()
            });
        }

        const { email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            if (!user) {
                console.log("❌ User not found:", email);
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            console.log("✅ User found:", user.email);
            console.log("🔐 DB Password:", user.password);
            console.log("🔑 Input Password:", password);

            const isMatch = await bcrypt.compare(password, user.password);
            console.log("Password match result:", isMatch);

            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            const payload = {
                user: {
                    id: user.id,
                    userType: user.userType
                }
            };

            jwt.sign(
                payload,
                process.env.JWT_SECRET,
                { expiresIn: '5d' },
                (err, token) => {
                    if (err) throw err;
                    res.json({ token, userType: user.userType });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).json({ message: 'Server error during login' });
        }
    }
);

// ========================== GET USER ==========================
// Example: fetch user profile after login
const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

router.get('/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
