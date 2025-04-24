const dotenv = require("dotenv");
dotenv.config();

const JenkinsTestApi = require("jenkins");

import { jobsListSchema } from "../../src/entitis/connectorsSpecific/JenkinsTypes";

if (process.env.JENKINS_URL) {
  const jenkinsConfig = {
    baseUrl: `http://${process.env.JENKINS_USER}:${process.env.JENKINS_TOKEN}@${process.env.JENKINS_URL}`,
    promisify: true,
  };

  const jenkins = JenkinsTestApi(jenkinsConfig);

  describe("jenkins", () => {
    it("list jobs test", async () => {
      const data = await jenkins.job.list();

      const jobParsingResult = jobsListSchema.safeParse(data);

      if (!jobParsingResult.success) {
        console.error(JSON.stringify(jobParsingResult));
      }

      expect(jobParsingResult.success).toBe(true);
    });

    // it("Job info", async () => {
    //   const dataConf = await jenkins.job.config(process.env.JENKINS_TEST_REPO);
    //   expect(dataConf !== null).toBe(true);

    //   const parser = new XMLParser();
    //   let jObj: jenkinsJob = parser.parse(dataConf, {
    //     parseAttributeValue: false,
    //     ignoreAttributes: true,
    //   });

    //   const jobParsingResult = jobSchema.safeParse(jObj);

    //   if (!jobParsingResult.success) {
    //     console.error(JSON.stringify(jobParsingResult));
    //   }

    //   expect(jobParsingResult.success).toBe(true);
    // });

    // it("Get Jobs Info", async () => {
    //   const jobInfo = await jenkins.job.get(process.env.JENKINS_TEST_REPO);

    //   const jobParsingResult = buildJobSchema.safeParse(jobInfo);

    //   if (!jobParsingResult.success) {
    //     console.error(JSON.stringify(jobParsingResult));
    //   }

    //   expect(jobParsingResult.success).toBe(true);
    // });
  });
} else {
  describe("Jenkins not configured", () => {
    it("No Jenkins URL", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
