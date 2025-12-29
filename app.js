const express = require("express");
const mongoose = require("mongoose");
const Course = require("./models/courses");
const User = require("./models/user");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { authenticateToken, authorizeTeachersOnly } = require("./models/auth");

const app = express();
const router = express.Router();
const secret = process.env.JWT_SECRET;

// Middleware (parse JSON)
app.use(express.json());
app.use(bodyParser.json());

// ✅ CORS (MUST be before routes)
const corsOptions = {
  origin: function (origin, callback) {
    const allowed = [
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "https://engelken-course-manager.netlify.app", // ✅ NO trailing slash
    ];

    // allow requests with no origin (Postman, curl, server-to-server)
    if (!origin) return callback(null, true);

    if (allowed.includes(origin)) return callback(null, true);

    return callback(new Error(`CORS blocked origin: ${origin}`), false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-auth"], // ✅ include x-auth
  credentials: false, // you are not using cookies, so keep false
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
// ✅ ensure preflight always works
app.options("*", cors(corsOptions));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected!"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// Routes

// Get all courses
router.get("/courses", authenticateToken, async (req, res) => {
  try {
    const { enrolled, owner, search } = req.query;
    let query = {};

    if (enrolled === "true") {
      query.enrolledUsers = req.user._id;
    } else if (owner) {
      if (!owner || owner === "undefined" || !/^[0-9a-fA-F]{24}$/.test(owner)) {
        return res.status(400).json({ error: "Invalid owner ID" });
      }
      query.owner = owner;
    }

    if (search) {
      query.$or = [
        { courseId: { $regex: search, $options: "i" } },
        { courseName: { $regex: search, $options: "i" } },
      ];
    }

    const courses = await Course.find(query);
    res.json(courses);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// Create new user (ONLY ONCE)
router.post("/users", async (req, res) => {
  if (!req.body || !req.body.username || !req.body.password || !req.body.role) {
    return res
      .status(400)
      .json({ error: "Missing username, password, or role" });
  }

  const allowedRoles = ["student", "teacher"];
  const role = allowedRoles.includes(req.body.role) ? req.body.role : "student";

  const newUser = new User({
    username: req.body.username,
    password: req.body.password,
    role,
  });

  try {
    await newUser.save();
    res.sendStatus(201);
  } catch (err) {
    console.error("User creation error:", err);
    res
      .status(500)
      .json({ error: "Failed to create user", details: err.message });
  }
});

// User login
router.post("/auth", async (req, res) => {
  if (!req.body || !req.body.username || !req.body.password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  const user = await User.findOne({ username: req.body.username });

  if (!user || user.password !== req.body.password) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  const token = jwt.sign(
    { _id: user._id.toString(), username: user.username, role: user.role },
    secret,
    { expiresIn: "1h" }
  );

  res.json({
    username: user.username,
    role: user.role,
    token,
    _id: user._id,
    auth: 1,
  });
});

// Create course
router.post(
  "/courses",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    try {
      const course = new Course({
        ...req.body,
        owner: req.user._id,
        enrolledUsers: [req.user._id],
      });
      await course.save();
      res.status(201).json(course);
    } catch (error) {
      res.status(400).json({ message: error.message });
    }
  }
);

router.get("/courses/:id", async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).send("Course not found");
    res.json(course);
  } catch (err) {
    res.status(400).send(err);
  }
});

router.put(
  "/courses/:id",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (
      req.user.role !== "teacher" ||
      course.owner.toString() !== req.user._id.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized to edit this course" });
    }

    Object.assign(course, req.body);
    await course.save();
    res.json(course);
  }
);

router.delete(
  "/courses/:id",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (
      req.user.role !== "teacher" ||
      course.owner.toString() !== req.user._id.toString()
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this course" });
    }

    await course.deleteOne();
    res.json({ message: "Course deleted" });
  }
);

router.post("/courses/:id/enroll", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (course.enrolledUsers.includes(req.user._id)) {
      return res
        .status(400)
        .json({ message: "User already enrolled in this course" });
    }

    course.enrolledUsers.push(req.user._id);
    await course.save();
    res.json({ message: "Successfully enrolled in course" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

router.post("/courses/:id/drop", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    course.enrolledUsers = course.enrolledUsers.filter(
      (userId) => userId.toString() !== req.user._id.toString()
    );
    await course.save();
    res.json({ message: "Successfully dropped the course" });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// Use router
app.use("/api", router);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
