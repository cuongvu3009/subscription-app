import express, { json } from 'express'
const router = express.Router()
import {body, validationResult } from 'express-validator'
import bcrypt from "bcryptjs";
import JWT from 'jsonwebtoken'
import User from '../models/User'


router.post('/signup', 
//1. validate the email and password 
body('email').isEmail().withMessage('Email is invalid'), 
body('password').isLength({min: 5}).withMessage('Password is invalid') , 
async (req, res) => {	
//2. custom errors 
const validationErrors = validationResult(req)

if (!validationErrors.isEmpty()) {
	const errors = validationErrors.array().map((error) => {
		return {
			msg: error.msg
		}
	})
	return res.json({errors, data: null})
}
//3. check if email exists
const {email, password} = req.body

const user = await User.findOne({email})

if (user) {
	return res.json({
		errors: [
			{
				msg: 'This email is in use'
			}
		], 
		data: null,
	})
}

//4. hash password
const hashedPassword = await bcrypt.hash(password, 10)

//5. create user and save to db
const newUser = await User.create({
	email,
	password: hashedPassword
})

//6. send back token
const token = await JWT.sign(
	{email: newUser.email}, 
	process.env.JWT_SECRET as string, 
	{expiresIn: '3h'}
); 

res.json({
	errors: [], 
	data: {
		token, 
		user: {
			id: newUser._id,
			email: newUser.email
}}})
})

router.post('/login', async(req, res) => {
//1. get user from db
	const {email, password} = req.body

	const user = await User.findOne({email})

	if (!user) {
		return res.json({
			errors: [
				{
					msg: "Invalid credentials"
				},
			], 
			data: null
		})
	}
//2. compare the hased password
	const isMatch = await bcrypt.compare(password, user.password)

	if (!isMatch) {
		return res.json({
			errors: [
				{
					msg: "Invalid credentials"
				}
			],
			data: null
		})
	}

//3. send back token
	const token = await JWT.sign(
		{email: user.email},
		process.env.JWT_SECRET as string, 
		{
			expiresIn: '3d'
		}
	)

	return res.json({
		errors: [],
		data: {
			token,
			user: {
				id: user._id,
				email: user.email
			}
		}
	})
})

export default router
