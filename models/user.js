const db = require('../db');

// User Schema
const User = db.model("User", {
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['student', 'teacher'],
        default: 'student',
        required: true
    }
});

module.exports = User;