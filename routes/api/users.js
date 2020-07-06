const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/', 
    [
        check('name', 'Name is required').not().isEmpty(),
        check('email', 'Please include a valid email').isEmail(),
        check('password', 'Please enter a password with 6 or more characters').isLength({ min: 6 })
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty){
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        try {
            // See if user exists
            let user = await User.findOne({ email: email });

            // If user exists already
            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exists '}] }); // same error formatting as express-validator error array
            }

            // If user NOT found
            // Get user's gravatar
            const avatar = gravatar.url(email, {
                s: '200', // size
                r: 'pg',  // rating
                d: 'mm'   // default image
            })

            // Create new instance of User
            user = new User({
                name: name, 
                email: email,
                avatar: avatar,
                password: password
            })

            // Encrypt password
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            // Save new User
            await user.save();
        
            // Return jsonwebtoken----

            const payload = {
                user: {
                    id: user.id  // We are using the default _id that comes w/ Mongo objects
                }
            }

            // jwt.sign(payload, secret, optional extra params, callback)
            jwt.sign(
                payload, 
                config.get('jwtSecret'), 
                { expiresIn: 360000 }, 
                (err, token) => {
                    if (err) throw err;

                    res.json({ token });
                });

        } catch(err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }

        
    }
);

module.exports = router;