const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const connectDB = require("./db");
const Course = require("./models/courses");
const User = require("./models/user");
const { authenticateToken, authorizeTeachersOnly } = require("./models/auth");

const app = express();
const router = express.Router();

const secret = process.env.JWT_SECRET;

// CORS
const allowedOrigins = new Set([
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "http://localhost:3000",
  "https://engelken-course-manager.netlify.app",
]);

const corsOptions = {
  origin: (origin, cb) => {
    // allow requests with no origin
    if (!origin || allowedOrigins.has(origin)) return cb(null, true);
    return cb(null, false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-auth", "Authorization"],
  optionsSuccessStatus: 204,
};

// Apply CORS to all requests
app.use(cors(corsOptions));

app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return cors(corsOptions)(req, res, () => res.sendStatus(204));
  }
  next();
});

app.use(express.json());
app.use(bodyParser.json());

// Get all courses
router.get("/courses", authenticateToken, async (req, res) => {
  try {
    const { enrolled, owner, search } = req.query;
    const query = {};

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
    console.error("GET /courses error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// Create new user
router.post("/users", async (req, res) => {
  const { username, password, role } = req.body || {};

  if (!username || !password || !role) {
    return res
      .status(400)
      .json({ error: "Missing username, password, or role" });
  }

  const allowedRoles = ["student", "teacher"];
  const safeRole = allowedRoles.includes(role) ? role : "student";

  const newUser = new User({
    username,
    password,
    role: safeRole,
  });

  try {
    await newUser.save();
    return res.sendStatus(201);
  } catch (err) {
    console.error("POST /users error:", err);

    // duplicate username
    if (err && err.code === 11000) {
      return res.status(409).json({ error: "Username already exists" });
    }

    return res.status(500).json({ error: "Failed to create user" });
  }
});

// User login
router.post("/auth", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  try {
    const user = await User.findOne({ username });

    if (!user || user.password !== password) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { _id: user._id.toString(), username: user.username, role: user.role },
      secret,
      { expiresIn: "1h" }
    );

    return res.json({
      username: user.username,
      role: user.role,
      token,
      _id: user._id,
      auth: 1,
    });
  } catch (err) {
    console.error("POST /auth error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

// Create course (teachers only)
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
      return res.status(201).json(course);
    } catch (error) {
      console.error("POST /courses error:", error);
      return res.status(400).json({ message: error.message });
    }
  }
);

// Get course by ID
router.get("/courses/:id", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).send("Course not found");
    return res.json(course);
  } catch (err) {
    console.error("GET /courses/:id error:", err);
    return res.status(400).send(err);
  }
});

// Update course (teacher + owner)
router.put(
  "/courses/:id",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    try {
      const course = await Course.findById(req.params.id);
      if (!course) return res.status(404).json({ message: "Course not found" });

      if (course.owner.toString() !== req.user._id.toString()) {
        return res
          .status(403)
          .json({ message: "Not authorized to edit this course" });
      }

      Object.assign(course, req.body);
      await course.save();
      return res.json(course);
    } catch (err) {
      console.error("PUT /courses/:id error:", err);
      return res.status(400).json({ message: err.message || "Update failed" });
    }
  }
);

// Delete course (teacher + owner)
router.delete(
  "/courses/:id",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    try {
      const course = await Course.findById(req.params.id);
      if (!course) return res.status(404).json({ message: "Course not found" });

      if (course.owner.toString() !== req.user._id.toString()) {
        return res
          .status(403)
          .json({ message: "Not authorized to delete this course" });
      }

      await course.deleteOne();
      return res.json({ message: "Course deleted" });
    } catch (err) {
      console.error("DELETE /courses/:id error:", err);
      return res.status(400).json({ message: err.message || "Delete failed" });
    }
  }
);

// Enroll in a course
router.post("/courses/:id/enroll", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    if (course.enrolledUsers.includes(req.user._id)) {
      return res
        .status(400)
        .json({ message: "User already enrolled in this course" });
    }

    course.enrolledUsers.push(req.user._id);
    await course.save();
    return res.json({ message: "Successfully enrolled in course" });
  } catch (error) {
    console.error("POST /courses/:id/enroll error:", error);
    return res.status(400).json({ message: error.message });
  }
});

// Drop a course
router.post("/courses/:id/drop", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    if (!course.enrolledUsers.includes(req.user._id)) {
      return res
        .status(400)
        .json({ message: "User not enrolled in this course" });
    }

    course.enrolledUsers = course.enrolledUsers.filter(
      (userId) => userId.toString() !== req.user._id.toString()
    );

    await course.save();
    return res.json({ message: "Successfully dropped the course" });
  } catch (error) {
    console.error("POST /courses/:id/drop error:", error);
    return res.status(400).json({ message: error.message });
  }
});

// Use the router
app.use("/api", router);

const PORT = process.env.PORT || 3000;

// Start server after DB connection
connectDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  });
