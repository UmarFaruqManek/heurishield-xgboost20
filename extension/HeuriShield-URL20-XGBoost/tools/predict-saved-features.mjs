// Offline audit: stdin = JSON array of saved URL20 feature objects; stdout = probabilities.
// The extension itself never stores or forwards these probabilities.
import fs from "node:fs";
import { predictProbability } from "../src/model/xgboost-engine.js";

const model = JSON.parse(fs.readFileSync(new URL("../src/model/xgboost-url20.json", import.meta.url)));
const values = JSON.parse(fs.readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(values.map(features => predictProbability(model, features))));
