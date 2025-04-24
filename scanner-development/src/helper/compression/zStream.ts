const { deflateSync, unzip } = require("zlib");
const zlib = require("zlib");

export function compress(text, bestCompression = false) {
  //
  // Increase Global Counter and log
  if (bestCompression) {
    let buffer = zlib.gzipSync(text, {
      level: zlib.constants.Z_BEST_COMPRESSION,
    });

    return buffer.toString("base64");
  }
  let buffer = deflateSync(text);

  return buffer.toString("base64");
}

// I assume buffer is base64!!!
export function uncompress(buffer) {
  return new Promise((resolve, reject) => {
    unzip(Buffer.from(buffer, "base64"), (err, buffer) => {
      if (err) reject(err);
      resolve(buffer.toString());
    });
  });
}

export function binaryUncompress(buffer) {
  return new Promise((resolve, reject) => {
    unzip(buffer, function (err, buffer) {
      if (err) reject(err);
      resolve(buffer.toString());
    });
  });
}
