import { MongoClient } from "mongodb";
import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

const getMongoUri = (): string => {
  if (process.env.MONGO_CONN === "atlas") {
    return `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_HOST}`;
  } else if (process.env.MONGO_CONN === "local") {
    return `${process.env.MONGO_URI_CONNECTION}`;
  } else if (process.env.MONGO_CONN === "aws") {
    return `mongodb+srv://${process.env.MONGO_HOST}`;
  } else {
    throw `wrong mongo server passed: ${process.env.MONGO_CONN}`;
  }
};

let isOpen = null;
const uri = getMongoUri();
const client = new MongoClient(uri, {
  monitorCommands: true,
  connectTimeoutMS: 100000,
  maxPoolSize: 30,
  socketTimeoutMS: 360000,
  appName: "ox-scanner-service-artifacts",
});

const clientPromise = async () => {
  if (!isOpen) {
    await client.connect();
    isOpen = true;
  }
  return client;
};

export default clientPromise;
