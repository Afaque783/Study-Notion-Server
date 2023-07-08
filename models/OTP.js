const mongoose = require("mongoose");
const mailSender = require("../utils/mailSender");

const OTPSchema = new mongoose.Schema({
    email : {
        type : String,
        required : true,
    },
    otp : {
        type : String,
        required : true,
    },
    createdAt : {
        type : Date,
        default : Date.now(),
        expires : 5*60,
    }

});

// Functionn To Send Emails

async function sendVerificationEmail(email , otp) {

    try{
        const mailResponse = await mailSender(email,"Verificationn Email From studyNotion",otp);
        console.log("Email sent Successfully" , mailResponse);
    }
    catch(error) {
        console.log("error while sending the verification email",error);
        throw error;
    }
}

OTPSchema.pre("save",async function(next){
    await sendVerificationEmail(this.email,this.otp);
    next();
})

module.exports = mongoose.model("OTP",OTPSchema);