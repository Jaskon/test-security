const nvt = require("node-virustotal");
import loggerImport from "../../logger";
import crypto from "crypto";
const logger = loggerImport.getDebugLogger();
const regexExtractIp = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
let vtAPI = null;
let repCash = new Map();
var urlLib = require("url");
const isValidDomain = require("is-valid-domain");

class VTHelper {
  uuid: string;
  private static instance: VTHelper;

  private constructor() {}

  public static getInstance(): VTHelper {
    if (!VTHelper.instance) {
      VTHelper.instance = new VTHelper();
      VTHelper.instance.init();
    }

    return VTHelper.instance;
  }

  init() {
    if (vtAPI == null) {
      logger.info(`Try init vt reputation`);
      vtAPI = nvt.makeAPI(500);
      vtAPI.setKey(
        "f557676cab07a11e1a4e784d0e85e40c4d1ad6635aee5c594532d462fca403d2", // move to .env
      );
      logger.info(`Finish init vt reputation`);
    }
  }

  // seems to be unused - please deprecate
  getVerdict(verdicts) {
    const isMal = verdicts.some(verdict => verdict === "suspicious");
    const isSusp = verdicts.some(verdict => verdict === "malicious");

    if (isMal) return "malicious";
    if (isSusp) return "suspicious";
    return "unknown";
  }

  getCalssification(rep) {
    // previous rule values :
    // malicious > 1
    // suspicious > 2

    if (rep == null) {
      return "unknown";
    }

    const malicious = rep.data.attributes.last_analysis_stats.malicious;
    const suspicious = rep.data.attributes.last_analysis_stats.suspicious;
    const harmless = rep.data.attributes.last_analysis_stats.harmless;

    if (malicious > 3) {
      return "malicious";
    }
    if (suspicious > 3 || suspicious + malicious > 3) {
      return "suspicious";
    }
    if (harmless > 10) {
      return "harmless";
    }
    return "unknown";
  }

  getDomainFromUrl(url) {
    try {
      const res = urlLib.parse(url).hostname;
      return res;
    } catch (err) {
      logger.error(`err: ${err}, url: ${url}`);
    }
    return null;
  }

  getIpFromUrl(url) {
    try {
      const res = url.match(regexExtractIp);
      if (res != null) return res[0] == "" ? null : res[0];
    } catch (err) {
      logger.error(`err: ${err}, url: ${url}`);
    }
    return null;
  }

  getIpRep(ip) {
    try {
      if (vtAPI == null) {
        logger.warn("vt api disabled");
        return null;
      }

      ip = VTHelper.instance.getIpFromUrl(ip);

      if (vtAPI == null || ip === "" || ip == null) {
        return null;
      }

      logger.debug(`Try to get ip rep for ${ip}`);

      const fromCash = repCash.get(ip);
      if (fromCash != undefined) {
        return fromCash;
      }

      return new Promise((resolve, reject) => {
        vtAPI.ipLookup(ip, function (err, res) {
          logger.debug(`return rep ${ip}`);
          if (err) {
            if (!VTHelper.instance.isNotFoundErr(err)) {
              try {
                logger.error(`getIpRep Promise err: ${JSON.stringify(err)}, ip: ${ip}`);
              } catch (err) {}
            }
            return resolve(null);
          }

          const rep = JSON.parse(res);
          repCash.set(ip, rep);

          return resolve(rep);
        });
      });
    } catch (err) {
      logger.error(`getIpRep err: ${err}, ip: ${ip}`);
    }
  }

  getURLRep(url) {
    try {
      if (vtAPI == null || url === "" || url == null) {
        return null;
      }

      logger.debug(`Try to get url rep for ${url}`);

      const fromCash = repCash.get(url);
      if (fromCash != undefined) {
        return fromCash;
      }

      return new Promise((resolve, reject) => {
        vtAPI.urlLookup(url, function (err, res) {
          logger.debug(`return rep ${url}`);
          if (err) {
            if (!VTHelper.instance.isNotFoundErr(err)) {
              try {
                logger.error(`getURLRep Promise err: ${JSON.stringify(err)}, url: ${url}`);
              } catch (err) {}
            }
            return resolve(null);
          }

          const rep = JSON.parse(res);
          repCash.set(url, rep);

          return resolve(rep);
        });
      });
    } catch (err) {
      logger.error(`getURLRep err: ${err}, url: ${url}`);
    }
  }

  getDomainRep(domain) {
    try {
      domain = VTHelper.instance.getDomainFromUrl(domain);
      if (!isValidDomain(domain)) {
        return null;
      }

      if (vtAPI == null || domain === "" || domain == null) {
        return null;
      }

      logger.debug(`Try to get domain rep for ${domain}`);

      const fromCash = repCash.get(domain);
      if (fromCash != undefined) {
        return fromCash;
      }

      return new Promise((resolve, reject) => {
        vtAPI.domainLookup(domain, function (err, res) {
          logger.debug(`return rep ${domain}`);
          if (err) {
            if (!VTHelper.instance.isNotFoundErr(err)) {
              try {
                logger.error(`VT getDomainRep Promise err: ${JSON.stringify(err)}, domain: ${domain}`);
              } catch (err) {}
            }
            return resolve(null);
          }

          const rep = JSON.parse(res);
          repCash.set(domain, rep);

          return resolve(rep);
        });
      });
    } catch (err) {
      logger.error(`getDomainRep err: ${err}, domain: ${domain}`);
    }
  }

  isNotFoundErr(err) {
    try {
      const res = JSON.parse(err);
      if (res.error.code === "NotFoundError") return true;
    } catch (err) {}
    return false;
  }

  checkSpecificReputation(webhook, reputation) {
    return false;

    for (const webhookRep of webhook.reputationData) {
      if (webhookRep == null) {
        continue;
      }
      const rep = VTHelper.getInstance().getCalssification(webhookRep);
      if ([reputation].some(i => rep.toLowerCase() == i.toLowerCase())) {
        return true;
      }
    }
    return false;
  }

  getVtWebLink(webhookUrl) {
    try {
      const url = new URL(webhookUrl).href;
      const sha = crypto.createHash("sha256").update(url).digest("hex");
      const vtLink = new URL(`https://www.virustotal.com/gui/url/${sha}`).href;
      return vtLink;
    } catch (err) {
      logger.error(`error when trying to build a vt web (not api) link for ${webhookUrl}`);
    }
    return "";
  }
}

export default VTHelper;
