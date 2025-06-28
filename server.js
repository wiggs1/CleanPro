
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { Parser } = require('json2csv');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;
const HOST = '127.0.0.1';

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

const bookingSchema = new mongoose.Schema({
  name: String,
  email: String,
  date: String,
  service: String,
  notes: String
});

const adminSchema = new mongoose.Schema({
  username: String,
  password: String
});

const Booking = mongoose.model('Booking', bookingSchema);
const Admin = mongoose.model('Admin', adminSchema);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.post('/api/bookings', async (req, res) => {
  try {
    const newBooking = new Booking(req.body);
    await newBooking.save();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: req.body.email,
      subject: 'Booking Confirmation',
      text: `Hi ${req.body.name}, your ${req.body.service} on ${req.body.date} is confirmed!`
    });
    res.status(201).json({ message: 'Booking saved and email sent' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save booking or send email' });
  }
});

app.get('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const bookings = await Booking.find();
    res.status(200).json(bookings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

app.get('/api/bookings/csv', authenticateToken, async (req, res) => {
  try {
    const bookings = await Booking.find().lean();
    const parser = new Parser();
    const csv = parser.parse(bookings);
    res.header('Content-Type', 'text/csv');
    res.attachment('bookings.csv');
    return res.send(csv);
  } catch (err) {
    res.status(500).json({ error: 'Failed to export bookings' });
  }
});

app.post('/api/admin/register', authenticateToken, async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newAdmin = new Admin({ username, password: hashedPassword });
  await newAdmin.save();
  res.status(201).json({ message: 'Admin created' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const admin = await Admin.findOne({ username });
  if (!admin || !await bcrypt.compare(password, admin.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ username: admin.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
  require('child_process').exec(`start http://${HOST}:${PORT}`);
});
