const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");


//resetPasswordToken (mail Send Karne ka kaam iska hai)
exports.resetPasswordToken = async(req , res) => {
    try{
    //get email from req body
    const email = req.body.email;
    // check user for this email or validation
    const user = await User.findOne({email : email});
    if(!user){
        return res.json({
            success : false,
            message : 'Your email is not registered with us',
        });
    }
    // generate token
    const token = crypto.randomUUID();
    //update user by adding token and expiration time
    const updateDetails = await User.findOneAndUpdate(
                                                        {
                                                            email : email,
                                                        },
                                                        {
                                                            token : token,
                                                            resetPasswordToken : Date.now() + 5*60*100,
                                                        },
                                                        {
                                                            new : true,
                                                        }

                                                        );
    // create url
    const url = `http://localhost:3000/update-password/${token}`
    //send mail containing the url 
    await mailSender(email,
                    "Password Reset Link",
                    `Password Reset Link -->  ${url}`);

    // return response
    return res.json({
        success : true,
        message : 'Email Sent Successfully, Please Check email and Change Password',
    });

    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success : false,
            message : 'Something Went Wrong while Sending reset Passwword Email',
        }); 

    }

}

//resetPassword (db me update karne ka kaam iska hai)
exports.resetPassword = async(req , res) => {

    try{
        //Data Fetch
        const {password , confirmPassword , token} = req.body; 
        //validation
        if(password !== confirmPassword){
            return res.json({
                success : false,
                message : "Password is Not Matching",
            });
        }
        //get user Details from DB using token
        const userDetails = await User.findOne({token : token});
        // if no Entry - invaild Token
        if(!userDetails){
            return res.json({
                success : false,
                message : 'Token is invalid',
            });
        }
        // Token Time Check
        if(userDetails.resetPasswordExpires < Date.now()){
            return res.json({
                success : false,
                message : 'Token is Expired , Please Regenerate your Token',
            });
        }
        // hash Password
        const hashPassword = await bcrypt.hash(password,10);

        // Password update
        await User.findOne(
            {token:token},
            {password:hashPassword},
            {new:true},
        );
        // Return response
        return res.status(200).json({
            success : true,
            message : "Password Reset Successfully",
        });
    }
    catch(error){
        console.log(error);
        return res.status(500).json({
            success : false,
            message : "Something Went wrong in Reset Password Process",
        });

    }

}
