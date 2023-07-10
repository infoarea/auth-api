const User = require("../models/User");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken")

/**
 * @desc user login system
 * @route POST/login
 * @access PUBLIC
 * 
*/

const userLogin = asyncHandler( async(req, res) => {

    const {email, password} = req.body

    //validate
    if (!email || !password) {
        res.status(400).json({message: "All fields are required!"})
    }

    //check user
    const loginUser = await User.findOne({email})

    if (!loginUser) {
        res.status(400).json({message: "User not found!"})
    }

    //password check
    const passCheck = await bcrypt.compare(password, loginUser.password)

    if (!passCheck) {
        res.status(400).json({message: "Wrong password"})
    }

    //access token
    const accessToken = jwt.sign(
        {email : loginUser.email, role: loginUser.role}, 
        process.env.ACCESS_TOKEN_SECRET, 
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN} 
        );

    //Refresh token
    //     const refreshToken = jwt.sign(
    //     {email : loginUser.email}, 
    //     process.env.REFRESH_TOKEN_SECRET, 
    //     {expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN} 
    //     );
     
    res.cookie("accessToken", accessToken, {httpOnly : true, secure : false, maxAge: 1000 * 60 * 60 * 24 * 15})

    res.status(200).json({
        token : accessToken
    })
    
});


/**
 * @desc refresh Token
 * @route GET/refreshToken
 * @access PUBLIC
 * 
*/
const refreshToken = (req, res) =>{

    const cookies = req.cookies;
    
    if (!cookies?.rToken) {
      return  res.status(400).json({message: "invalid token request"})
    }
    const token = cookies.rToken;

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, asyncHandler( async(err, decode) =>{
        if (err) {
           return  res.status(400).json({message: "Token not match"})
        }

        const tokenUser = await User.findOne({ email: decode.email })
        if (!tokenUser) {
           return res.status(404).json({message: "Token user not found"})
        }

        //access token
        const accessToken = jwt.sign(
        {email : tokenUser.email, role: tokenUser.role}, 
        process.env.ACCESS_TOKEN_SECRET, 
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN} 
        );

        res.status(200).json({message: accessToken}) 
    })
    );

}

/**
 * @desc Logout
 * @route POST/logout
 * @access PUBLIC
 * 
*/
const userLogout = (req, res) =>{

    const cookies = req.cookies;

    if (!cookies?.rToken) {
      return res.status(400).json({message: "Already logged out!"})  
    }
    res.clearCookie("rToken", {
        httpOnly : true,
        secure : false
    }).json({message: "Logged out okay"})
}

module.exports = {
    userLogin,
    refreshToken,
    userLogout
}