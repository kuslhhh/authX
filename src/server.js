import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connect from "./config/mongo.js";
import authRouter from '../src/routes/authRoutes.js'

const app = express();
const port = process.env.PORT || 8080;
connect();

app.use(express.json());
app.use(cookieParser());
app.use(cors({ credentials: true }));

//API endpoint
app.get("/", (req, res) => {
  res.send("Api is running");
});

app.use("/api/v1/auth", authRouter);

app.listen(port, () => console.log(`Server is running on port ${port}`));
