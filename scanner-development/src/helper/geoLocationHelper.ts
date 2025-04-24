import loggerImport from "../logger";

const logger = loggerImport.getDebugLogger();
const geoip = require("geoip-lite");

class GeoLocationHelper {
  async findCountryByIP(ip: string) {
    try {
      const geo = await geoip.lookup(ip);
      if (geo == null || !geo) {
        return;
      }
      return geo.country;
    } catch (err) {
      logger.error(`failed get location by ip: ${ip}, ${err}`);
    }
  }
}

export default GeoLocationHelper;
