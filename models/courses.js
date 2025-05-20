const db = require('../db');

// Course Schema
const Course = db.model('Course', {
    instructor: { type: String, required: true },
    courseName: { type: String, required: true },
    courseId: { type: String, required: true, unique: true },
    courseDescription: { type: String, required: true },
    enrolled: { type: Boolean, default: false }, 
    dayOfWeek: { 
        type: String, 
        required: true
    },
    timeOfClass: { type: String, required: true },
    creditHours: { type: Number, required: true },
    owner: { type: db.Types.ObjectId, ref: 'User', required: true },
    enrolledUsers: [{ type: db.Types.ObjectId, ref: 'User' }],
    subjectArea : {type: String, required: true }
});

module.exports = Course;