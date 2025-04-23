import express from "express";
import bcrypt from "bcryptjs"
import User from "../models/user.model.js";
import { generateToken } from "../lib/utils.js";
import { protectRoute } from "../middleware/auth.middleware.js";


const router = express.Router();

router.post("/signup", async(req, res) => {
    console.log("Signup Route");
    const {email, fullName, password} = req.body;
    try {
        if(!email || !fullName || !password){
            return res.status(400).json({message: "All fields are required"});
        }
        if(password.length < 6){
            return res.status(400).json({message: "Password must be of at least 6 characters"});
        }

        const user = await User.findOne({email});
        if(user){
            return res.status(400).json({message: "Email already exists"});
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            fullName:fullName,
            email:email,
            password:hashedPassword,
        })

        if(newUser){
            generateToken(newUser._id, res);
            await newUser.save();
            res.status(201).json({message: "User Created"});
        }
        else{
            return res.status(400).json({message: "Invalid User data"});
        }
    } catch (error) {
        console.log("Error in signing up user");
        return res.status(500).json({message: "Internal Server Error", error: error.message});
    }
});

router.post("/login", async (req, res) => {
    const{email, password} = req.body;
    try {
        const user = await User.findOne({email});
        if(!user){
            return res.status(400).json({message: "Invalid Credentials!"});
        }

        const isPasswordCorrect = await bcrypt.compare(password, user.password);
        if(!isPasswordCorrect){
            return res.status(400).json({message:"Invalid Credentials!"});
        }

        generateToken(user._id,res);
        res.status(200).json({
            _id: user._id,
            fullName: user.fullName,
            email: user.email,
            profilePic: user.profilePic,
        })
    } catch (error) {
        console.log("Error in login route");
        return res.status(500).json({message: "Internal Server Error", error: error.message});
    }
});

router.post("/logout", (req, res) => {
    try {
        res.cookie("jwt", "", {maxAge:0});
        return res.status(200).json({message: "Logout Successfully"});
    } catch (error) {
        console.log("Error while logging out");
        return res.status(500).json({message: "Internal Server Error", error: error.message});        
    }
});


router.put("/update-profile",protectRoute,async(req, res)=>{
    
    try {
        
    } catch (error) {
        
    }
})
export default router;