const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const generateToken = require('../utils/generationToken');


exports.register = async (req, res) => {
console.log("Received request to register:", req.body);
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Please provide username and password' });
  }
  
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({
      username,
      password: hashedPassword
    });

    const token = generateToken(newUser._id);
    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};


exports.login = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Please provide username and password' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = generateToken(user._id);
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};


exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
