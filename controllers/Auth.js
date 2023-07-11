const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();



//SendOTP

exports.sendOTP = async (req,res) => {
    try{
        const {email} = req.body;

        const checkUserPresent = await User.findOne({email});

        if(checkUserPresent){
            return res.status(401).json({
                success : false,
                message : "User Already Registered",
            })
        }

        // Generate Otp achcha tareeka company me jaake seekhenge ye brute force

        var otp = otpGenerator.generate(6,{
            upperCaseAlphabets : false,
            lowerCaseAlphabets : false,
            specialChars : false,
        })
        console.log("OTP Generated -> ",otp);
        const result = await OTP.findOne({otp:otp});

        while(result){
            otp = otpGenerator(6,{
                upperCaseAlphabets : false,
                lowerCaseAlphabets : false,
                specialChars : false,
            });

            result = await OTP.findOne({otp:otp});
        }

        const otpPayload = {email,otp};

        // entry in db for otp 

        const otpBody = await OTP.create(otpPayload);
        console.log(otpBody);

        res.status(200).json({
            success : true,
            message : "OTP Sent Successfully",
            otp,
        })
    }
    catch(error){
        console.log(error);
        res.status(500).json({
            success : false,
            message : error.message,
        })
    }
}

//SignUp

exports.signUp = async (req,res) => {
    try{

    //data fetch from req
    const {
        firstName,
        lastName,
        email,
        password,
        accountType,
        confirmPassword,
        contactNumber,
        otp
    } = req.body;
    // validate karo
    if(!firstName || !lastName || !password || !confirmPassword || !otp || !email){
        return res.status(403).json({
            success : false,
            message : "All Fields are Required",
        });
    }
    // 2 password ko match karlo
    if(password !== confirmPassword){
        return res.status(400).json({
            success : false,
            message : "Passwod And ConfirmPassword Does not Match, Please Try Again",
        });
    }
    // check user already exist
    const existingUser = await User.findOne({email});
    if(existingUser){
        return res.status(400).json({
            success : false,
            message : " User is Already Register",
        });
    }


    // find most recent opt
    const recentOTP = await User.findOne({email}).sort({createdAt:-1}).limit(1);
    console.log(recentOTP);
    // validate otp
    if(recentOTP.length == 0){
        return res.status(400).json({
            success : false,
            message : "OTP Not Found",
        });
    }else if(otp !== recentOTP.otp){
        return res.status(400).json({
            success : false,
            message : "Invalid OTP",
        });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password,10);

    //entry Create in DB
    const profileDetails = await Profile.create({
        gender : null,
        dateOfBirth : null,
        about : null,
        contactNumber : null,
    });

    const user = await User.create({
        firstName,
        lastName,
        email,
        password : hashedPassword,
        additionalDetails : profileDetails._id,
        accountType,
        image : `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
    })

    // return response
    return res.status(200).json({
        success : true,
        message : 'User is Registered Successfully',
        user,
    });
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success : false,
            message : "User is Not Registered Please Try Again",
        });

    }
}

//Login
exports.login = async (req,res) => {
    try {

        // Get details from req body
        const {email, password} = req.body;

        //validation of data
        if(!email || !password){
            return res.status(403).json({
                success : false,
                message  : "All fields are required, please try again",
            });
        }
        //user check exist or not
        const user = await User.findOne({email}).populate("additionalDetails");
        if(!user){
            return res.status(401).json({
                success : false,
                message : "User is Not Registered, Please try again",
            });
        }
        //generate JWT after password matching
        if(await bcrypt.compare(password,user.password)){
            const payload = {
                email : user.email,
                id : user._id,
                accountType : user.accountType,
            }
            const token = jwt.sign(payload,process.env.JWT_SECRET,{
                expiresIn:"2h",
            });
            user.token = token;
            user.password = undefined;
            // create cookie and send response
            const options = {
                expires : new Date(Date.now() + 3*24*60*60*1000),
                httpOnly : true,
            }

            res.cookie("token",token,options).status(200).json({
                success : true,
                user,
                token,
                message : "Logged in successfully"
            })
        }else{
            return res.status(401).json({
                success : false,
                message : "Password is Incorrect",
            });
        }   
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success : false,
            message : 'Login failure, Please try again ',
        });
    }
}

// changePassword
exports.changePassword = async(req , res) => {

    // get data from req body
    //  get oldpassword ,newpassword,confirmpassword
    // validation
    
    // update password in DB
    // send mail - password updated
    //return response
}