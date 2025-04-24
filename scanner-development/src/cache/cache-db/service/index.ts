import clientPromise from "../../mongo-db/client/client";
import del from "./delete";
import get from "./get";
import set from "./set";
import replace from "./replace";
import cindex from "./cindex";

const cacheDB = {
  get: get(clientPromise),
  set: set(clientPromise),
  replace: replace(clientPromise),
  del: del(clientPromise),
  cindex: cindex(clientPromise),
};

export default cacheDB;
