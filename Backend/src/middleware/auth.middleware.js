import jwt from "jsonwebtoken";
import User from "../models/user.model.js";

export const protectRoute   = async(req, res) =>{
    try {
        const token = req.cookies.jwt;

        if(!token){
            return res.status(400).json({message: "Unauthoried"});
        }

        const decoded = jwt.verify(token, process.emv.JWT_SECRET);
        if(!decoded){
            return res.status(400).json({message: "Unauthoried - Token is invalid"});
        }

        const user = await User.findById(decoded.userId).select("-password");

        if(!user){
            return res.status(400).json({message: "User not found"});
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json({message: "Middleware error", error: error.message});
    }
}