const mongoose = require("mongoose");

const courseSchema = new mongoose.Schema({
  courseId: { type: String, required: true, unique: true },
  courseName: { type: String, required: true },
  courseDescription: { type: String },
  instructor: { type: String, required: true },
  dayOfWeek: { type: String },
  timeOfClass: { type: String },
  creditHours: { type: Number },
  subjectArea: { type: String },
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  enrolledUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
});

const Course = mongoose.model("Course", courseSchema);

module.exports = Course;
