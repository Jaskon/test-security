require("dotenv").config();

import AWS from "aws-sdk";
import * as fs from "fs";
import loggerImport from "../../logger";
const path = require("path");
const { zipDirectory } = require("./archiver");
const logger = loggerImport.getDebugLogger();

const s3 = new AWS.S3({
  accessKeyId: process.env.REPORT_BUCKET_AWS_ACCESS_KEY,
  secretAccessKey: process.env.REPORT_BUCKET_AWS_SECRET_ACCESS_KEY,
});

const uploadFileInternal = async (fileFullPath, fileName) => {
  return new Promise((resolve, reject) => {
    const data = fs.readFileSync(fileFullPath);
    const params = {
      Bucket: process.env.REPORT_BUCKET, // pass your bucket name
      Key: `reports/${fileName}`, // file will be saved as ox-poc-reports/fileName
      Body: data,
    };
    s3.upload(params, function (s3Err, data) {
      if (s3Err) {
        logger.error(`Error uploading to S3, with error:` + s3Err);
        reject(s3Err);
      } else {
        logger.info(`File uploaded successfully at ${data.Location}`);
        resolve(true);
      }
    });
  });
};

const getFiles = async dir => {
  const subdirs = fs.readdirSync(dir);
  const files = await Promise.all(
    subdirs.map(async subdir => {
      const res = path.resolve(dir, subdir);
      return fs.statSync(res).isDirectory() ? getFiles(res) : res;
    }),
  );
  return files.reduce((a, f) => a.concat(f), []);
};

export function uploader() {
  return {
    uploadFile: async (fileFullPath, fileName) => {
      await uploadFileInternal(fileFullPath, fileName);
    },

    uploadZipped: async (dirToUpload: string, outputDirName: string) => {
      try {
        logger.info(`about to upload Zipped folder: ${dirToUpload}`);
        const isoDate = new Date().toISOString().replace(/:/g, "_");
        const zipName = `${isoDate}.zip`;
        const zipPath = path.join(__dirname, zipName);
        await zipDirectory(dirToUpload, zipPath);

        if (fs.existsSync(dirToUpload)) {
          fs.rmSync(dirToUpload, { recursive: true });
        }

        const fileName = `${outputDirName}/${zipName}`;
        await uploadFileInternal(zipPath, fileName);

        fs.unlinkSync(zipPath);
      } catch (error) {
        logger.error("fail to upload zipped", error);
      }
    },
  };
}
