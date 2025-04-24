import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

import * as fs from "fs";
const archiver = require("archiver");

/**
 * @param {String} source
 * @param {String} out
 * @returns {Promise}
 */
export function zipDirectory(source, out) {
  logger.info(`zipping src folder: ${source}, destination path: ${out}`);

  const archive = archiver("zip", { zlib: { level: 9 } });
  const stream = fs.createWriteStream(out);

  return new Promise((resolve, reject) => {
    archive
      .directory(source, false)
      .on("error", err => {
        logger.error(`fail to zip`, err);
        reject(err);
      })
      .pipe(stream);

    stream.on("close", () => resolve(true));
    archive.finalize();
  });
}
