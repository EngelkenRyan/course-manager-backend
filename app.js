const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs"); // ← added for password hashing
require("dotenv").config();

const Course = require("./models/courses");
const User = require("./models/user"); // note: you had "users.js" earlier – make sure filename matches
const { authenticateToken, authorizeTeachersOnly } = require("./models/auth");

const app = express();
const router = express.Router();

// ────────────────────────────────────────────────
// CORS – this is the main fix for your current error
// ────────────────────────────────────────────────
app.use(
  cors({
    origin: [
      "http://localhost:5500",
      "http://127.0.0.1:5500",
      "https://your-app-name.netlify.app", // ← replace with your real Netlify URL after deploy
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "x-auth"],
    credentials: true,
  })
);

// Explicitly handle OPTIONS preflight requests (helps on Render)
app.options("*", cors());

// Optional: log preflights to confirm they're reaching the server
app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    console.log(
      `OPTIONS preflight from origin: ${req.headers.origin || "unknown"}`
    );
  }
  next();
});

// ────────────────────────────────────────────────
// Middleware
// ────────────────────────────────────────────────
app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected!"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// JWT secret check
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error("JWT_SECRET is not set in environment variables");
  process.exit(1);
}

// ────────────────────────────────────────────────
// Routes
// ────────────────────────────────────────────────

// Get all courses (with filters: enrolled, owner, search)
router.get("/courses", authenticateToken, async (req, res) => {
  try {
    const { enrolled, owner, search } = req.query;
    let query = {};

    if (enrolled === "true") {
      query.enrolledUsers = req.user._id;
    } else if (owner) {
      if (!/^[0-9a-fA-F]{24}$/.test(owner)) {
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
    console.error("Get courses error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// Register new user (with password hashing)
router.post("/users", async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res
      .status(400)
      .json({ error: "Missing username, password, or role" });
  }

  const allowedRoles = ["student", "teacher"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    console.error("User creation error:", err);
    res
      .status(500)
      .json({ error: "Failed to create user", details: err.message });
  }
});

// Login
router.post("/auth", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing username or password" });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const token = jwt.sign(
      { _id: user._id.toString(), username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      role: user.role,
      username: user.username,
      _id: user._id.toString(),
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// ────────────────────────────────────────────────
// Course routes (teacher protected where needed)
// ────────────────────────────────────────────────

router.post(
  "/courses",
  authenticateToken,
  authorizeTeachersOnly,
  async (req, res) => {
    try {
      const course = new Course({
        ...req.body,
        owner: req.user._id,
        enrolledUsers: [], // usually empty at creation – owner not auto-enrolled
      });
      await course.save();
      res.status(201).json(course);
    } catch (error) {
      console.error("Create course error:", error);
      res.status(400).json({ message: error.message });
    }
  }
);

router.get("/courses/:id", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });
    res.json(course);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

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
      res.json(course);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  }
);

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
      res.json({ message: "Course deleted" });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);

router.post("/courses/:id/enroll", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (course.enrolledUsers.includes(req.user._id)) {
      return res.status(400).json({ message: "Already enrolled" });
    }

    course.enrolledUsers.push(req.user._id);
    await course.save();
    res.json({ message: "Successfully enrolled" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post("/courses/:id/drop", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    course.enrolledUsers = course.enrolledUsers.filter(
      (id) => id.toString() !== req.user._id.toString()
    );
    await course.save();
    res.json({ message: "Successfully dropped" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Mount all routes under /api
app.use("/api", router);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
