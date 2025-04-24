import { execSync } from "child_process";
import { promises as fsp } from "fs";
import { stat } from "node:fs/promises";
import loggerImport from "../../logger";
import dependencyFiles from "../../policy/org/config/dependencyFiles.json";
const logger = loggerImport.getDebugLogger();
const fs = require("fs");
const path = require("path");
const nthline = require("nthline");
const Timeout = require("await-timeout");
const { readdir } = require("fs").promises;

class FileHelper {
  uuid: string;
  constructor(uuid: string) {
    this.uuid = uuid;
  }

  write(path: string, dataJS: string, base64: boolean = false) {
    try {
      logger.debug(`try write to: ${path}`);

      const dirName = require("path").dirname(path);
      this.createDir(dirName);

      let text = dataJS;
      if (base64) {
        text = Buffer.from(dataJS, "base64").toString("ascii");
        fs.writeFileSync(path, text);
        return;
      }

      fs.writeFileSync(path, text);
    } catch (err) {
      logger.error(`failed  write to: ${path}, err: ${err}`);
    }
  }

  writeStream(path: string, data: []) {
    try {
      logger.debug(`try write to create write stream: ${path}`);
      const dirName = require("path").dirname(path);
      this.createDir(dirName);
      // Create a write stream to the output file
      const outputStream = fs.createWriteStream(path);
      // Write the opening bracket for the JSON array
      outputStream.write("[");

      // Loop over the JSON array and write each object to the file
      data.forEach((obj, index) => {
        // Write a comma before all objects except the first
        if (index !== 0) {
          outputStream.write(",");
        }
        // Write the JSON object to the file
        outputStream.write(JSON.stringify(obj, null, 2));
      });

      // Write the closing bracket for the JSON array
      outputStream.write("]");

      // Close the write stream
      outputStream.end();

      // Listen for the 'finish' event to know when the write operation is complete
      outputStream.on("finish", () => {
        logger.debug("write stream operation completed");
      });
    } catch (err) {
      logger.error(`failed  write to: ${path}, err: ${err}`);
    }
  }

  getFileNameAccordingToLinkPage(pathInfo, repoName) {
    const normalizedPath = pathInfo.split(path.sep).join(path.posix.sep);
    const normalizedRepoName = repoName.split(path.sep).join(path.posix.sep);
    const index = normalizedPath.indexOf(normalizedRepoName);
    if (index == -1) {
      return pathInfo;
    }

    pathInfo = normalizedPath.substring(index + normalizedRepoName.length, normalizedPath.length);

    if (pathInfo.startsWith("\\")) {
      pathInfo = pathInfo.substring("\\".length);
    } else if (pathInfo.startsWith("/")) {
      pathInfo = pathInfo.substring("/".length);
    }
    return pathInfo;
  }

  async getFolderSizeWithTimeout(path: string) {
    try {
      logger.info(`try get repo size ${path}`);

      if (process.platform === "linux") {
        // Alpine docker has an older command
        const linuxCommand = `du -s .`;

        const stdout = await Timeout.wrap(execSync(linuxCommand, { cwd: path }).toString(), 1000 * 30, "repo size rom disk timeout");

        const match = /^(\d+)/.exec(stdout);
        const kiloBytes = Number(match[1]);
        const bytes = kiloBytes * 1000;

        return bytes;
      }
    } catch (err) {
      logger.error(`failed get repo size from path: ${path}`, err);
    }
    return 0;
  }

  async getFileSize(filePath: string) {
    try {
      if (!fs.existsSync(filePath)) {
        return 0;
      }

      const stats = await fsp.stat(filePath);
      const fileSizeInBytes = stats.size;
      return fileSizeInBytes;
    } catch (err) {
      logger.error(`failed to get file size from path: ${filePath}, err: ${err}`);
    }
    return 0;
  }

  deleteFile(path: string) {
    try {
      if (!fs.existsSync(path)) {
        return;
      }
      //logger.info(`try delete file from path: ${path}`);
      fs.unlinkSync(path);
    } catch (err) {
      logger.error(`failed to delete file path: ${path}, err: ${err}`);
    }
  }

  async getContentByLine(filePath: string, line: number, content: string = "") {
    try {
      if (filePath === "") {
        throw `failed get line by content, file path: ${filePath} is empty`;
      }
      if (!fs.existsSync(filePath)) {
        throw `failed get line by content, file path: ${filePath} not exist`;
      }

      const l = line > 0 ? line - 1 : line;

      if (!content) {
        const lineContent = await nthline(l, filePath);
        if (lineContent) {
          return lineContent;
        }
      }

      let leakFileContent = content;
      if (!leakFileContent) {
        const stats = fs.statSync(filePath);
        const fileSizeInBytes = stats.size;
        const fileSizeInMegabytes = fileSizeInBytes / (1024 * 1024);

        if (fileSizeInMegabytes > 5) {
          logger.warn(`failed get line by content, file, lineNumber: ${line}, path: ${filePath} size: ${fileSizeInMegabytes} to big`);
          return "";
        }
        leakFileContent = fs.readFileSync(filePath, "utf8");
      }
      const linesInfo = leakFileContent.split(/\r?\n/);
      let lineNum = 1;
      for (const lineInfo of linesInfo) {
        if (line == lineNum) {
          return lineInfo;
        }
        lineNum++;
      }
    } catch (err) {
      logger.error(`failed get line by content in file: ${filePath}, err: ${err}`);
    }
    return "";
  }

  getLineByContent(filePath: string, info: string, secondaryInfo: string = null) {
    try {
      if (filePath === "") {
        throw `failed to check line for file content, file path: ${filePath} is empty`;
      }
      if (info === "") {
        throw `failed to check line for file content, info is empty`;
      }

      if (!fs.existsSync(filePath)) {
        return -1;
      }

      const stats = fs.statSync(filePath);
      const fileSizeInBytes = stats.size;
      const fileSizeInMegabytes = fileSizeInBytes / (1024 * 1024);

      if (fileSizeInMegabytes > 3) {
        return -1;
      }

      let leakFileContent = fs.readFileSync(filePath, "utf8");
      const linesInfo = leakFileContent.split("\n");
      let lineNum = 1;
      for (const lineInfo of linesInfo) {
        //Add to existing code files
        if (!secondaryInfo && lineInfo.includes(info)) {
          return lineNum;
        } else if (lineInfo.includes(info) && lineInfo.includes(secondaryInfo)) {
          return lineNum;
        }
        lineNum++;
      }
    } catch (err) {
      logger.error(`failed to check line for file content in file: ${filePath}, err: ${err}`);
    }
    return -1;
  }

  createDir(dir: string) {
    try {
      logger.debug(`try create dir: ${dir}`);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    } catch (err) {
      logger.error(`failed create dir: ${dir}`, err);
    }
  }

  copyFolderRecursiveSync(source: string, target: string) {
    let files: string[] = [];

    // Check if folder needs to be created or integrated
    var targetFolder = path.join(target, path.basename(source));
    if (!fs.existsSync(targetFolder)) {
      fs.mkdirSync(targetFolder, { recursive: true });
    }

    // Copy
    if (fs.lstatSync(source).isDirectory()) {
      files = fs.readdirSync(source);
      for (let file of files) {
        const curSource: string = path.join(source, file);
        if (fs.lstatSync(curSource).isDirectory()) {
          this.copyFolderRecursiveSync(curSource, targetFolder);
        } else {
          this.copyFileSync(curSource, targetFolder);
        }
      }
    }
  }

  /**
   * Using native node API
   * @param src source filename to copy
   * @param dest destination filename of the copy operation
   */
  copyFile(src: string, dest: string): Promise<void> {
    return fsp.copyFile(src, dest);
  }

  // can cause `err: RangeError [ERR_FS_FILE_TOO_LARGE]: File size (***) is greater than 2 GB`
  copyFileSync(source: string, target: string) {
    let targetFile: string = target;

    // If target is a directory, a new file with the same name will be created
    if (fs.existsSync(target)) {
      if (fs.lstatSync(target).isDirectory()) {
        targetFile = path.join(target, path.basename(source));
      }
    }

    fs.writeFileSync(targetFile, fs.readFileSync(source));
  }

  async getPkgJsonDir() {
    const { dirname } = require("path");
    const {
      constants,
      promises: { access },
    } = require("fs");

    for (let path of module.paths) {
      try {
        let prospectivePkgJsonDir = dirname(path);
        await access(path, constants.F_OK);
        return prospectivePkgJsonDir;
      } catch (e) {}
    }
  }

  async getFiles(dir: string) {
    let arrayOfFiles = [];

    try {
      const allFiles = await this.getFileList(dir);

      allFiles.forEach(i =>
        arrayOfFiles.push({
          name: i,
          localDisk: true,
        }),
      );

      return arrayOfFiles;
    } catch (err) {
      logger.error(`failed get files dir: ${dir}, err: ${err}`);
    }
    return arrayOfFiles;
  }

  async getFileList(dirName) {
    let files = [];
    const items = await readdir(dirName, { withFileTypes: true });

    for (const item of items) {
      try {
        if (item.isDirectory()) {
          files = [...files, ...(await this.getFileList(`${dirName}/${item.name}`))];
        } else {
          files.push(`${dirName}/${item.name}`);
        }
      } catch (err) {
        logger.error(`failed get file list for dir: ${dirName}, err: ${err}`);
      }
    }
    return files;
  }

  readFile(filePath: string) {
    try {
      if (!fs.existsSync(filePath)) {
        return "";
      }

      logger.debug(`try read file path: ${filePath}`);
      const res = fs.readFileSync(filePath, "utf8");
      logger.debug(`finish read file path: ${filePath}`);
      return res;
    } catch (err) {
      logger.error(`failed read file path: ${filePath}, err: ${err}`);
    }
    return "";
  }

  async deleteAllFilesInRootDir(directory: string) {
    try {
      for (const file of await fsp.readdir(directory)) {
        if (file.endsWith(".done") || file.endsWith("imageFsAnalysis.json")) {
          continue;
        }
        //logger.info(`deleteAllFilesInRootDir file: ${directory}\\${file} `);
        await fsp.unlink(path.join(directory, file));
      }
    } catch (err) {
      logger.error(`failed delete root dir: ${directory}`, err);
    }
  }

  deleteDir(dir: string, recursive: boolean = true) {
    try {
      if (!fs.existsSync(dir)) {
        return;
      }

      fs.rmSync(dir, { recursive: recursive });
    } catch (err) {
      logger.error(`failed delete dir: ${dir}`, err);
    }
  }

  getLanguagesBasedOnDependencyFiles = files => {
    try {
      const languagesFromConfig = dependencyFiles.languages;
      const languages = new Set();
      for (const file of files) {
        for (const [lang, langExtentions] of Object.entries(languagesFromConfig)) {
          if (langExtentions.includes(file.name)) {
            languages.add(lang);
          }
        }
      }
      return [...languages];
    } catch (e) {
      logger.error(`failed to getLanguagesBasedOnDependencyFiles, err: ${e}`);
    }
    return [];
  };
}

const deleteFolderRecursive = (path: string) => {
  const tmpFileHelper = new FileHelper(path);

  if (process.env.KEEP_TELEMETRY_DATA !== "true") {
    tmpFileHelper.deleteDir(path);
  }
};

async function isExists(path) {
  try {
    await fs.access(path);
    return true;
  } catch {
    return false;
  }
}

export async function fileExists(path: string): Promise<boolean> {
  return stat(path)
    .then(() => true)
    .catch(() => false);
}

//
// Create file and folders if needed
//
async function extendedWriteFile(filePath, data) {
  try {
    const dirname = path.dirname(filePath);
    const exist = await isExists(dirname);
    if (!exist) {
      fs.mkdirSync(dirname, { recursive: true });
    }

    fs.writeFileSync(filePath, data, "utf8");
  } catch (err) {
    throw new Error(err);
  }
}

export default FileHelper;
export { deleteFolderRecursive, extendedWriteFile };
