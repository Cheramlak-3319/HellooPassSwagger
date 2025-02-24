// requires 
const SECRET ="This is my token logic";
const jwt = require("jsonwebtoken");
const users = [
    {username:'admin', password: 'admin'},
    {username:'user', password: 'user'},
    {username:'guest', password: 'guest'},
    // more users...
]
const _this = module.exports = {
    authenticate: async (username, password) => {
        try {
            const user = users.find(u => u.username === username && u.password === password);
            if(!user) throw new Error('Invalid username or password');
            token = await jwt.sign({username:username, status: 'valid'}, SECRET);
            // token = await Buffer.from([SECRET,username,password].join(':')).toString('base64');
            console.log(token);
            return token
        } catch (error) {
            console.log(error);
            throw error;
        }
    },
    verifyToken: async (token) => {
        try {
            // decoded = await Buffer.from(token, 'base64').toString('utf8');
            // [secret, username, password] = decoded.split(':');
            // console.log(username, password);
            // console.log(decoded);
            // return jwt.verify(token, SECRET);
            return jwt.verify(token, SECRET);
        } catch (error) {
            console.log(error);
            throw error;
        }
    }

}