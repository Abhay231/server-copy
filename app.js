const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');

const cors = require('cors');
const bodyParser = require('body-parser');
const authRouter = require('./routes/auth');
const app = express();
const port = 5500;
const crypto = require('crypto');
const secret = crypto.randomBytes(64).toString('hex');
console.log(secret);

// Middleware
app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB:', err));

// Routes
app.use('/auth', authRouter);

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
