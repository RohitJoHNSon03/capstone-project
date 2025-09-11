const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { isEmail, isMobilePhone } = require('validator');

const UserSchema = new mongoose.Schema({
    firstName: {
        type: String,
        required: [true, 'First name is required']
    },
    lastName: {
        type: String,
        required: [true, 'Last name is required']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        unique: true,
        validate: [isEmail, 'Please enter a valid email']
    },
    phone: {
        type: String,
        required: [true, 'Phone number is required'],
        unique: true,
        validate: {
            validator: (v) => isMobilePhone(v, 'any', { strictMode: false }),
            message: 'Please enter a valid phone number'
        }
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        minlength: [8, 'Password must be at least 8 characters']
    },
    userType: {
        type: String,
        enum: ['buyer', 'seller'],
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

// Password validation + hashing
UserSchema.pre('save', async function(next) {
    // Only run if password is modified
    if (!this.isModified('password')) return next();

    // Complexity check
    if (!/(?=.*\d)(?=.*[A-Z])(?=.*\W)/.test(this.password)) {
        return next(new Error('Password must contain uppercase, number, and special character'));
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

    next();
});

// Compare password method
UserSchema.methods.comparePassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);

