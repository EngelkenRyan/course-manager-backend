const express = require("express");
const mongoose = require("mongoose");
const Course = require("./models/courses");
const User = require("./models/user");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { authenticateToken, authorizeTeachersOnly } = require("./models/auth");

const app = express();
const router = express.Router();
const secret = process.env.JWT_SECRET;

// ----- CORS (FIXED) -----
// IMPORTANT: no trailing slash on netlify origin
const allowedOrigins = [
  "http://127.0.0.1:5500",
  "http://localhost:5500",
  "https://engelken-course-manager.netlify.app",
];

// Allow browser preflight + allow your custom header "x-auth"
const corsOptions = {
  origin: (origin, cb) => {
    // allow Postman / curl (no origin)
    if (!origin) return cb(null, true);

    if (allowedOrigins.includes(origin)) return cb(null, true);

    // if you want to debug mismatched origins, uncomment:
    // console.log("Blocked by CORS:", origin);

    return cb(new Error(`CORS blocked origin: ${origin}`), false);
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "x-auth"], // <-- THIS FIXES YOUR PREFLIGHT
  credentials: false, // you are not using cookies
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// Some setups still need explicit OPTIONS passthrough without using app.options('*')
app.use((req, res, next) => {
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ----- Middleware -----
app.use(express.json());

// ----- Mongo -----
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected!"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  });

// ----- Routes -----

// Health check (optional but SUPER helpful on Render)
router.get("/health", (req, res) => res.json({ ok: true }));

// Get all courses (auth required)
router.get("/courses", authenticateToken, async (req, res) => {
  try {
    const { enrolled, owner, search } = req.query;
    const query = {};

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
    console.error("GET /courses error:", err);
    res.status(500).json({ error: "Failed to fetch courses" });
  }
});

// Create new user (register)
router.post("/users", async (req, res) => {
  try {
    const { username, password, role } = req.body || {};
    if (!username || !password || !role) {
      return res
        .status(400)
        .json({ error: "Missing username, password, or role" });
    }

    const allowedRoles = ["student", "teacher"];
    const safeRole = allowedRoles.includes(role) ? role : "student";

    const newUser = new User({ username, password, role: safeRole });
    await newUser.save();

    return res.status(201).json({ message: "User created" });
  } catch (err) {
    console.error("POST /users error:", err);
    // common: duplicate username
    if (err?.code === 11000) {
      return res.status(409).json({ error: "Username already exists" });
    }
    return res.status(500).json({ error: "Failed to create user" });
  }
});

// Login
router.post("/auth", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "Missing username or password" });
    }

    const user = await User.findOne({ username });
    if (!user || user.password !== password) {
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
  } catch (err) {
    console.error("POST /auth error:", err);
    res.status(500).json({ error: "Login failed" });
  }
});

// Create course (teacher only)
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
    } catch (err) {
      console.error("POST /courses error:", err);
      res.status(400).json({ message: err.message });
    }
  }
);

// Get course by ID
router.get("/courses/:id", async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).send("Course not found");
    res.json(course);
  } catch (err) {
    console.error("GET /courses/:id error:", err);
    res.status(400).send(err);
  }
});

// Update course (teacher + owner only)
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
      console.error("PUT /courses/:id error:", err);
      res.status(400).json({ message: err.message });
    }
  }
);

// Delete course (teacher + owner only)
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
      console.error("DELETE /courses/:id error:", err);
      res.status(400).json({ message: err.message });
    }
  }
);

// Enroll
router.post("/courses/:id/enroll", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    if (
      course.enrolledUsers.some(
        (id) => id.toString() === req.user._id.toString()
      )
    ) {
      return res
        .status(400)
        .json({ message: "User already enrolled in this course" });
    }

    course.enrolledUsers.push(req.user._id);
    await course.save();
    res.json({ message: "Successfully enrolled in course" });
  } catch (err) {
    console.error("POST /courses/:id/enroll error:", err);
    res.status(400).json({ message: err.message });
  }
});

// Drop
router.post("/courses/:id/drop", authenticateToken, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) return res.status(404).json({ message: "Course not found" });

    course.enrolledUsers = course.enrolledUsers.filter(
      (userId) => userId.toString() !== req.user._id.toString()
    );
    await course.save();

    res.json({ message: "Successfully dropped the course" });
  } catch (err) {
    console.error("POST /courses/:id/drop error:", err);
    res.status(400).json({ message: err.message });
  }
});

app.use("/api", router);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
