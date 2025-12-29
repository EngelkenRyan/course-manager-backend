const express = require('express');
const Course = require('./models/courses');
const User = require('./models/user');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const { authenticateToken, authorizeTeachersOnly } = require('./models/auth');

const app = express();
const router = express.Router();

const secret = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());
app.use(bodyParser.json());

// Get all courses 
router.get('/courses', authenticateToken, async (req, res) => {
  try {
    const { enrolled, owner, search } = req.query;
    let query = {};
    
    if (enrolled === 'true') {
      query.enrolledUsers = req.user._id;
    } else if (owner) {
      if (!owner || owner === 'undefined' || !/^[0-9a-fA-F]{24}$/.test(owner)) {
        return res.status(400).json({ error: 'Invalid owner ID' });
      }
      query.owner = owner;
    }
    
    if (search) {
      query.$or = [
        { courseId: { $regex: search, $options: 'i' } },
        { courseName: { $regex: search, $options: 'i' } }
      ];
    }

    const courses = await Course.find(query);
    res.json(courses);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch courses' });
  }
});

// Create new user
router.post('/users', async (req, res) => {
  if (!req.body.username || !req.body.password || !req.body.role) {
    return res.status(400).json({ error: "Missing username, password, or role" });
  }

  const allowedRoles = ['student', 'teacher'];
  const role = allowedRoles.includes(req.body.role) ? req.body.role : 'student';

  const newUser = new User({
    username: req.body.username,
    password: req.body.password,
    role: role
  });

  try {
    await newUser.save();
    res.sendStatus(201);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create user" });
  }
});

// User login 
router.post('/auth', async (req, res) => {
  if (!req.body.username || !req.body.password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  let user = await User.findOne({ username: req.body.username });

  if (!user || user.password !== req.body.password) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = jwt.sign(
    { _id: user._id.toString(), username: user.username, role: user.role },
    secret,
    { expiresIn: '1h' }
  );
  res.json({
    username: user.username,
    role: user.role,
    token: token,
    _id: user._id,
    auth: 1
  });
});

// Create course
router.post('/courses', authenticateToken, authorizeTeachersOnly, async (req, res) => {
  try {
    if (req.user.role !== 'teacher') {
      return res.status(403).json({ message: 'Only teachers can add courses' });
    }

    const course = new Course({
      ...req.body,
      owner: req.user._id,
      enrolledUsers: [req.user._id] 
    });

    await course.save();
    res.status(201).json(course);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Get course by ID 
router.get('/courses/:id', async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).send('Course not found');
    }
    res.json(course);
  } catch (err) {
    res.status(400).send(err);
  }
});

// Update course 
router.put('/courses/:id', authenticateToken, authorizeTeachersOnly, async (req, res) => {
  const course = await Course.findById(req.params.id);
  if (!course) return res.status(404).json({ message: 'Course not found' });

  if (req.user.role !== 'teacher' || course.owner.toString() !== req.user._id.toString()) {
    return res.status(403).json({ message: 'Not authorized to edit this course' });
  }

  Object.assign(course, req.body);
  await course.save();
  res.json(course);
});

// Delete course 
router.delete('/courses/:id', authenticateToken, authorizeTeachersOnly, async (req, res) => {
  const course = await Course.findById(req.params.id);
  if (!course) return res.status(404).json({ message: 'Course not found' });

  if (req.user.role !== 'teacher' || course.owner.toString() !== req.user._id.toString()) {
    return res.status(403).json({ message: 'Not authorized to delete this course' });
  }

  await course.deleteOne();
  res.json({ message: 'Course deleted' });
});

// Enroll in a course
router.post('/courses/:id/enroll', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (course.enrolledUsers.includes(req.user._id)) {
      return res.status(400).json({ message: 'User already enrolled in this course' });
    }

    course.enrolledUsers.push(req.user._id);
    await course.save();
    res.json({ message: 'Successfully enrolled in course' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Drop a course
router.post('/courses/:id/drop', authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (!course.enrolledUsers.includes(req.user._id)) {
      return res.status(400).json({ message: 'User not enrolled in this course' });
    }

    course.enrolledUsers = course.enrolledUsers.filter(userId => userId.toString() !== req.user._id.toString());
    await course.save();
    res.json({ message: 'Successfully dropped the course' });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.use("/api", router);
app.listen(3000, () => console.log("Server running on http://localhost:3000"));