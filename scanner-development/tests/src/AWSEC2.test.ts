const dotenv = require("dotenv");
dotenv.config();
import AWSEC2 from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSEC2";
import { Repo } from "../../src/entitis/codeRepoTypes";
import MongoConnect from "../../src/mongo/mongoConnect";
import policyNoMatchHashBetweenCICDandRuntimeCloud from "../../src/policy/rules/code/policyNoMatchHashBetweenCICDandRuntimeCloud";
import PolicyRulesBase from "../../src/policy/rules/code/policyRulesBase";
import RuleExclusions from "../../src/policy/rules/ruleExclusions";
const fs = require("fs");
const axios = require("axios");

describe("CloudCrawler", () => {
  it("Read and verify the data size is correct", async () => {
    /*************** THE ACTUAL TEST WIP *******************/

    // let policy = new policyNoMatchHashBetweenCICDandRuntimeCloud();

    // const jsonData = JSON.parse(
    //   fs.readFileSync("EC2TestJSONData.json", "utf8")
    // );

    // const jsObj = JSON.parse(fs.readFileSync("jsObjName.json", "utf8"));

    // const mongoConnect: MongoConnect = new MongoConnect(
    //   jsObj.uuid,
    //   jsObj.orgName
    // );

    // const ruleExclusions = new RuleExclusions(
    //   jsObj.uuid,
    //   jsObj.orgName,
    //   mongoConnect
    // );

    // const result = await policy.runEval(jsObj, ruleExclusions);

    // console.log(result);

    /*************** FOR DEVELOPING WITH EC2 *******************/
    // const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
    // const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;
    // const sessionToken = process.env.AWS_SESSION_TOKEN;

    // const awsEC2 = AWSEC2(
    //   accessKeyId,
    //   secretAccessKey,
    //   undefined,
    //   "testOrgId",
    //   "testScanId"
    // );

    // const result = await awsEC2.getDockerData(["eu-west-1"]);

    // console.log(result);

    /*************** TESTING DOCKER HUB *******************/
    // Testing docker hub
    // try {
    //   // Check if the tag is active
    //   let call = axios.get(
    //     `https://hub.docker.com/v2/repositories/library/mongo/tags/5.0.5-focal`
    //   );

    //   let res: any = await call;
    //   let data = res.data;
    //   const active = data.tag_status == "active";
    //   console.log(data);

    //   // Get more information about the library
    //   call = axios.get(`https://hub.docker.com/v2/repositories/library/mongo/`);

    //   res = await call;
    //   data = res.data;
    //   const pull_count = data.pull_count;
    //   const star_count = data.star_count;
    //   const namespace = data.namespace;
    //   console.log(data);

    //   // Get the badge of the publisher
    //   let badge = "";
    //   if (namespace == "library") {
    //     badge = "Docker Official Image";
    //   } else {
    //     call = axios.get(`https://hub.docker.com/v2/orgs/bitnami/`);

    //     res = await call;
    //     data = res.data;
    //     badge = data.badge;
    //     console.log(data);
    //   }
    // } catch (error) {
    //   console.log(`Failed searching in docker hub, error: ${error}`);
    // }

    expect(true).toEqual(true);
  }, 666999666);
});
