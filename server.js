import express from "express";
import cors from "cors";
import fetch from "node-fetch";

const app = express();

app.use(cors({ origin: "*" }));

app.get("/", async (req, res) => {
  if (typeof req.query.url !== "string") {
    return res.send();
  }
  let encodedString = Buffer.from(req.query.url)
    .toString("base64")
    .replace(/=/g, "");
    console.log(encodedString);
    console.log(new Date())

  const options = {
    method: "GET",
    headers: {
      Accept: "application/json",
      "x-apikey":
        process.env.KEY,
    },
  };
  const response = await fetch(
    "https://www.virustotal.com/api/v3/urls/" + encodedString,
    options
  )
  
  const data = await response.json();
  res.send(data)
});

app.listen(process.env.PORT || 4000);
