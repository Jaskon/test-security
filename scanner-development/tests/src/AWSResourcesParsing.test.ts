import * as fs from "fs";
import { AWSResources } from "../../src/entitis/connectorsSpecific/AWSRelatedTypes";

describe("Serialized resources analysis", () => {
  const data: any = JSON.parse(fs.readFileSync(process.cwd() + "/tests/src/AWSMockData/OXResources.json", "utf8"));

  it("test parsing abilities of AWStorage", () => {
    const parsedResources: AWSResources = data;
    expect(parsedResources.ResourceTagMappingList.length).toEqual(1832);

    // Detect all possible resources
    // arn:aws:ec2:eu-west-1:857809147732:instance/i-0e567f52ba3bbaafc
    const ec2RegEx = /arn:aws:ec2:([^:]+?):(\d+):instance\/(i-[a-zA-Z0-9]+)/;

    // arn:aws:ecs:eu-west-1:857809147732:task-definition/betaapp:12
    const ecsRegEx = /arn:aws:ecs:([^:]+?):(\d+):task-definition\/([a-zA-Z0-9:\-_]+)/;

    // arn:aws:lambda:eu-west-1:857809147732:function:pdf-service-staging-graphql
    const lambdaRegEx = /arn:aws:lambda:([^:]+?):(\d+):function:([a-zA-Z0-9:\-_]+)/;

    let lambdaCounter = 0;
    let ec2Counter = 0;
    let ecsCounter = 0;

    for (const resource of parsedResources.ResourceTagMappingList) {
      if (resource.ResourceARN?.startsWith("arn:aws:ec2:eu-west-1:857809147732:instance/i-")) {
        if (ec2RegEx.exec(resource.ResourceARN)) {
          ec2Counter++;
        } else {
          expect(false).toBeTruthy();
        }
      } else if (resource.ResourceARN?.startsWith("arn:aws:ecs:eu-west-1:857809147732:task-definition")) {
        if (ecsRegEx.exec(resource.ResourceARN)) {
          ecsCounter++;
        } else {
          expect(false).toBeTruthy();
        }
      } else if (resource.ResourceARN?.startsWith("arn:aws:lambda:eu-west-1:857809147732:function:")) {
        if (lambdaRegEx.exec(resource.ResourceARN)) {
          lambdaCounter++;
        } else {
          expect(false).toBeTruthy();
        }
      }
    }

    expect(lambdaCounter).toBe(83);
    expect(ecsCounter).toBe(313);
    expect(ec2Counter).toBe(4);
  });
});
