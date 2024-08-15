require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const parser = require('body-parser');
const bcrypt = require('bcryptjs');
const Login_model = require('./models/login');
const Feedback_model = require('./models/Feedback');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3001;

app.use(cors());
app.use(parser.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI);

const transporter = nodemailer.createTransport({
    service: 'gmail', // Use 'gmail' or another email service
    auth: {
        user: process.env.EMAIL_USER, // Your email address
        pass: process.env.EMAIL_PASS  // Your email password or app-specific password
    }
});


app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.post('/register', async (req, res) => {
    try {
        const user = await Login_model.findOne({ email: req.body.email });
        if (user) {
            return res.status(400).send({
                message: "Email already exists",
                status: 400
            });
        }
        if (req.body.confirmPassword !== req.body.password) {
            return res.status(400).send({
                message: "Passwords do not match",
                status: 400
            });
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        req.body.password = hashedPassword;
        await Login_model.create(req.body);
        res.status(201).send({
            message: "Registered successfully",
            status: 201,
            data: req.body
        });
    } catch (e) {
        res.status(500).send({
            message: "Error occurred during registration",
            status: 500,
            error: e.message
        });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await Login_model.findOne({ email: email });
        if (!user) {
            return res.status(404).send({
                message: "User not found",
                status: 404
            });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({
                message: "Incorrect password",
                status: 401
            });
        }
        res.status(200).send({
            message: "Login successful",
            status: 200,
            data: user
        });
    } catch (e) {
        res.status(500).send({
            message: "Login failed",
            status: 500,
            error: e.message
        });
    }
});

app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await Login_model.findOne({ email: email });
        if (!user) {
            return res.status(404).send({
                message: "User not found",
                status: 404
            });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                   Please click on the following link, or paste this into your browser to complete the process:\n\n
                   http://localhost:5173/reset-password/${user._id}/${token}\n\n
                   If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).send({
                    message: "Failed to send email",
                    status: 500,
                    error: error.message
                });
            }
            res.status(200).send({
                message: "Password reset email sent successfully",
                status: 200,
                data: email
            });
        });
    } catch (e) {
        res.status(500).send({
            message: "An error occurred",
            status: 500,
            error: e.message
        });
    }
});

app.post("/reset-password/:id/:token", async (req, res) => {
    const { newPassword } = req.body;
    const { id, token } = req.params;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.id !== id) {
            return res.status(401).send({
                message: "Invalid token",
                status: 401
            });
        }

        const user = await Login_model.findOne({ _id: id });
        if (!user) {
            return res.status(404).send({
                message: "User not found",
                status: 404
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();

        res.status(200).send({
            message: "Password reset successful",
            status: 200
        });
    } catch (e) {
        res.status(500).send({
            message: "An error occurred",
            status: 500,
            error: e.message
        });
    }
});

app.post('/connect', async (req, res) => {
    try {
        const user = await Login_model.findOne({ email: req.body.email });
        if (!user) {
            return res.status(400).send({
                message: "Register with the given email to connect",
                status: 400
            });
        }
        await Feedback_model.create(req.body);
        res.status(200).send({
            message: "Your message was received successfully",
            status: 200
        });
    } catch (e) {
        res.status(500).send({
            message: "An error occurred",
            status: 500,
            error: e.message
        });
    }
});

app.post("/subscribe", async (req, res) => {
    const email = req.body.Email;
    if (!email) {
        return res.status(400).send({
            message: "Email is required",
            status: 400
        });
    }

    try {
        const user = await Login_model.findOne({ email });
        if (!user) {
            return res.status(401).send({
                message: "Please login to subscribe",
                status: 401
            });
        }

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Welcome Aboard Your Cosmic Voyage!',
            text: `Congratulations! ${user.name} You’ve just embarked on an extraordinary journey with Cosmic Voyage. Prepare to explore the wonders of the universe and stay tuned for stellar updates, exclusive content, and intergalactic adventures. Thank you for joining our cosmic crew!`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).send({
            message: "Subscribed successfully",
            status: 200
        });
    } catch (error) {
        res.status(500).send({
            message: "Failed to subscribe. Please try again later.",
            status: 500,
            error: error.message
        });
    }
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
