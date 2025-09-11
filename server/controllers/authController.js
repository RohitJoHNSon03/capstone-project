const User = require('../models/User');
console.log('Loaded User model from:', require.resolve('../models/User'));
console.log('Type of User:', typeof User);
console.log('User keys:', Object.keys(User));

const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');

// Generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        {
            id: user._id,
            userType: user.userType
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
    );
};

// @route   POST api/auth/register
// @desc    Register user
exports.register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { firstName, lastName, email, phone, password, userType } = req.body;

    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        user = new User({
            firstName,
            lastName,
            email,
            phone,
            password,
            userType
        });

        await user.save();

        const token = generateToken(user);

        res.status(201).json({
            token,
            userType: user.userType,
            message: 'Registration successful'
        });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: err.message || 'Server error' });
    }
};

// @route   POST api/auth/login
// @desc    Login user
exports.login = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { loginId, password } = req.body;

    try {
        // Check if loginId is email or phone
        const isEmail = loginId.includes('@');
        let user;

        if (isEmail) {
            user = await User.findOne({ email: loginId });
        } else {
            user = await User.findOne({ phone: loginId });
        }

        if (!user) {
            console.log("❌ No user found with", loginId);
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Debug logs
        console.log("Entered password:", password);
        console.log("Stored hash from DB:", user.password);

        // Compare password
        const isMatch = await user.comparePassword(password);
        console.log("Password match result:", isMatch);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = generateToken(user);

        res.json({
            token,
            userType: user.userType,
            message: 'Login successful'
        });
    } catch (err) {
        console.error("Login error:", err);
        res.status(400).json({ message: err.message || 'Server error' });
    }
};



// @route   GET api/auth/user
// @desc    Get user data
exports.getUser = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: err.message || 'Server error' });
    }
};
