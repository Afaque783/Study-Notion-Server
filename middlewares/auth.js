const jwt = require("jsonwebtoken");
require("dotenv").config();
const User = require("../models/User");

//auth
exports.auth = async(req , res, next) => {
    try{
        //extract token 
        const token = req.cookies.token 
                                    || req.body.token
                                    || req.header("Authorisation").replace("Bearer" , "");
        
        // if Token is Misssing return Response
        if(!token){
            return res.status(401).json({
                success : false,
                Message : "Token is Missing",
            });
        }

        //Verify Token by Secret Key
        try{

            const decode = jwt.verify(token,process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode;

        }catch(err){
            return res.status(401).json({
                success : false,
                message : "Token is invalid",
            });
        }
        next();
    }
    catch(error){
        return res.status(401).json({
            success : false,
            message : "Something went wrong while validating the Token",
        });
    }
}

//isStudent
exports.isStudent = async(req , res ,next) => {

    try{
        if(req.user.accountType !== "Student"){
            return res.status(401).json({
                success : false,
                message : "this is Protected Route For Student only",
            });
        }
        next();

    }catch(error){
        return res.status(401).json({
            success : false,
            message : "Something went wrong while validating the Student"
        });
    }

}

//isInstructor

exports.isInstructor = async(req , res ,next) => {

    try{
        if(req.user.accountType !== "Instructor"){
            return res.status(401).json({
                success : false,
                message : "this is Protected Route For Instructor only",
            });
        }
        next();

    }catch(error){
        return res.status(401).json({
            success : false,
            message : "Something went wrong while validating the Instructor"
        });
    }

}

//isAdmin

exports.isAdmin = async(req , res ,next) => {

    try{
        if(req.user.accountType !== "Admin"){
            return res.status(401).json({
                success : false,
                message : "this is Protected Route For Admin only",
            });
        }
        next();

    }catch(error){
        return res.status(401).json({
            success : false,
            message : "Something went wrong while validating the Admin"
        });
    }

}