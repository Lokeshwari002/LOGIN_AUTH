const express=require("express")
const cors=require("cors")
const mysql=require("mysql2")
const bodyParser=require("body-parser")
const bcrypt=require("bcrypt")
const jwt=require("jsonwebtoken")
require("dotenv").config();



let app=express()
app.use(cors())

app.use(bodyParser.json())


const db=mysql.createConnection({
    host:process.env.DB_HOST,
    user:process.env.DB_USER,
    password:process.env.DB_PASSWORD,
    database:process.env.DB_NAME,
    port:process.env.DB_PORT
})

db.connect((err)=>{
if(err){
    console.log("connection failed",err)
}
else{
    console.log("connected successfully")
}
})

const PORT=process.env.DB_PORT

app.listen(PORT,()=>{
    console.log(`port is listening at ${PORT}`)
})


// app.post("/signup", (req, res) => {
//     const { user_name, email, password } = req.body;

//     if (!user_name || !email || !password) {
//         return res.status(400).json({ message: "All fields are required" });
//     }

//     const checkUserSql = "SELECT * FROM signup WHERE email = ?";
//     db.query(checkUserSql, [email], async (err, results) => {
//         if (err) {
//             console.error("Database error:", err);
//             return res.status(500).json({ message: "Internal server error" });
//         }

//         if (results.length > 0) {
//             return res.status(409).json({ message: "User already exists" });
//         }

//         try {
//             const hashedPassword = await bcrypt.hash(password, 10);
//             const insertUserSql = "INSERT INTO signup (user_name, email, password) VALUES (?, ?, ?)";

//             db.query(insertUserSql, [user_name, email, hashedPassword], (err, results) => {
//                 if (err) {
//                     console.error("Insert error:", err);
//                     return res.status(500).json({ message: "Error adding user" });
//                 }

//                 return res.status(201).json({ message: "User added successfully" });
//             });
//         } catch (hashError) {
//             console.error("Hashing error:", hashError);
//             return res.status(500).json({ message: "Error processing password" });
//         }
//     });
// });


const jwt_secret=process.env.JWT_SECRET

app.get("/",(req,res)=>{
    return res.send("auth backend is deployed on render")
})

app.post("/signup",(req,res)=>{
    const{user_name,email,password}=req.body;
    const sql="select * from signup where email=?"

    db.query(sql,[email],async(err,results)=>{
        if(results.length>0){
            return res.json("user already exists")
        }
       
        const hashPassword=await bcrypt.hash(password,10);

db.query("insert into signup(user_name,email,password) values(?,?,?)",[user_name,email,hashPassword],(err,results)=>{
    if(err){
        return res.json("error in adding user")
    }
    else{
        return res.json("User added successfully")
    }
})
})
})



// 
app.post("/login",(req,res)=>{
    const{email,password}=req.body;
    db.query("select * from signup where email=?",[email],async(err,results)=>{
        if(err||results.length===0){
            return res.json("error in email amd password")
        }
        const user=results[0]
        const isMatch=await bcrypt.compare(password,user.password)
        if(!isMatch){
            return res.json("error in email or password")
        }


        const token=jwt.sign(
            {id:user.id,email:user.email,user_name:user.user_name},
            jwt_secret,
            {expiresIn:"1h"}
        )
        return res.json({message:"Login successfull",token})




    })
})


// logout

app.post("/logout",(req,res)=>{
    return res.json("Logout successfully")
})

// middleware to verify token is valid or expired

function verifyToken(req,res,next){
    const jwt_secret="e866eacefa1a650a513625ae8c590cf257d80acc5cace2a319ad122d8aea6b51019312ee0baae559f3fb5da6f4855ef0a81f0fc3c8408435a60944850756138826068de5dfa73939f87277e24a5ca117d9d0b7d0815f01bb6610ee0cd31831c76f26d3f6d6cbfd96403f52e809b6fc39fd679a395ee20b86da008074f4226d514097337f36c177049489b2bd3944524da563d37d5f271a7515aba6eef3c3bb20c1c0934e1a2f24bda485e82283e7d8ec948160de72f5966bcbdb0a32957148fe";

const authHeader=req.headers.authorization;
if(!authHeader||!authHeader.startsWith("Bearer")){
    return res.json("Token Missing")
}

const token=authHeader.split(" ")[1];
try{
    const decoded=jwt.verify(token,jwt_secret);
    req.user=decoded;
    next()
}
catch(err){
    return res.json(err)
}

}

// protected route
app.get("/protected",verifyToken,(req,res)=>{
   return res.json({message:"welcome"+req.user.user_name})

})



    