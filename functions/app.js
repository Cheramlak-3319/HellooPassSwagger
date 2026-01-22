const express = require("express");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const path = require("path");
const auth = require("../auth.js"); // Assuming verifyToken is exported here
const cors = require("cors");

const swaggerDocument = YAML.load(path.join(__dirname, "swagger.yaml"));
const app = express();
const PORT = 4000;

app.use(cors());
app.use(express.json());

// 1. PUBLIC LOGIN ROUTE (For getting the token)
app.post("/login", (req, res) => {
  try {
    const { username, password } = req.body;
    const token = auth.authenticate(username, password);
    res.json({ success: true, token });
  } catch (err) {
    res.status(401).json({ success: false, error: err.message });
  }
});

// 2. CLEANER DOCUMENTATION ROUTE
// We move this ABOVE the global auth middleware if you want the docs public,
// OR keep it below if the whole site must be locked.
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// 3. GLOBAL AUTH FOR ACTUAL API ENDPOINTS
app.use("/api", auth.verifyToken);

app.listen(PORT, () => {
  console.log(`✅ Documentation: http://localhost:${PORT}/api-docs`);
  console.log(`🚀 API Base Path: http://localhost:${PORT}/api`);
});
