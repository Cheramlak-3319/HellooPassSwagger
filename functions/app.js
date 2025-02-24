const express = require("express");
const serverless = require("serverless-http");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");
// const auth = require('./auth');
// Load the swagger.yaml file
const swaggerDocument = YAML.load(path.join(__dirname, "swagger.yaml"));

const app = express();
const PORT = 5000;

// Serve Swagger UI at /api-docs
// app.post('/authenticate', (req, res) => {
//    const {username, password} = req.body;
//    auth.authenticate(username, password)
//    .then((response) => {
//       console.log(response);
//        res.status(200).json({token: response});
//    }).catch((err) => {
//        console.log(err);
//        res.status(403).json({error: 'Internal Server Error'}); //
//    })
//   }
// )
// app.use((req, res, next) => {
//   if(['api-docs','authenticate'].includes(req.path.split('/')[1])) {
//     let header = req.headers['Authorization'];
//     if(header) {
//       let token = header.split(' ')[1];
//       if(auth.verifyTokens(token)) {
//         next();
//       } else {
//         res.status(401).json({error: 'Unauthorized'});
//       }
//     }else {
//       res.status(403).json({error: 'Invalid Token'});
//       next(null)
//     }
//   }else {
//     res.status(403).json({error: 'Forbidden'});
//     next(null)
//   }
// })

app.use(express.static(path.join(__dirname, "public")));

app.use("/api/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Swagger UI available at http://localhost:${PORT}/api-docs`);
});
