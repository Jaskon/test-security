import { deflate, deflateSync, inflate, inflateSync, InputType } from "zlib";
import fs from "fs";
const archiver = require("archiver");

export function inflatePromise(buffer: InputType): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    inflate(buffer, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}

export function zipDirectory(sourceDir, outPath) {
  const archive = archiver("zip", { zlib: { level: 9 } });
  const stream = fs.createWriteStream(outPath);

  return new Promise<void>((resolve, reject) => {
    archive
      .directory(sourceDir, false)
      .on("error", err => reject(err))
      .pipe(stream);

    stream.on("close", () => resolve());
    archive.finalize();
  });
}

export function inflateS(buffer: InputType): Buffer {
  const inflate = inflateSync(buffer);
  return inflate;
}

export function deflateS(buffer: InputType): Buffer {
  const deflated = deflateSync(buffer);
  return deflated;
}

export function deflatePromise(buffer: InputType): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    deflate(buffer, (err, result) => {
      if (err) {
        reject(err);
      } else {
        resolve(result);
      }
    });
  });
}
