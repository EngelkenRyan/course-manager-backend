const mongoose = require('mongoose');

const mongoURI = process.env.MONGODB_URI || 'mongodb+srv://rengelken:rengelken2025@coursemanager.ftgihfe.mongodb.net/?retryWrites=true&w=majority&appName=CourseManager';

mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

module.exports = mongoose;