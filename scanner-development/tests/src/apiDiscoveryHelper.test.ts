const dotenv = require("dotenv");
dotenv.config();

import { ApiSecurityItem, ApiSecurityItemDef, ApiSecurityItemSource } from "../../src/entitis/apiTypes";
import { Repo } from "../../src/entitis/codeRepoTypes";
import APIDiscoveryHelper from "../../src/helper/service/apiDiscoveryHelper";

const fs = require("fs");

describe("API Discovery tests", () => {
  it("test saveFrameworkList", async () => {
    const repo: Repo = new Repo(
      "id",
      "",
      "",
      "name",
      "id",
      "",
      "",
      "n",
      "",
      false,
      "",
      0,
      false,
      false,
      false,
      "",
      false,
      [],
      1,
      0,
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      "",
      "",
      false,
      "",
    );

    repo.frameworks.add("FastAPI");
    repo.frameworks.add("Flask");

    const apiDiscoveryHelper: APIDiscoveryHelper = new APIDiscoveryHelper(Object(), "", "");
    await apiDiscoveryHelper.saveFrameworkList(repo, "test.json");
    const frameworks = JSON.parse(fs.readFileSync("test.json", "utf8"));
    fs.unlinkSync("test.json");
    expect(frameworks).toEqual({ frameworks: ["FastAPI", "Flask"] });
  });

  it("test extractAPIList", async () => {
    const repo: Repo = new Repo(
      "id",
      "",
      "",
      "name",
      "id",
      "",
      "",
      "n",
      "",
      false,
      "",
      0,
      false,
      false,
      false,
      "",
      false,
      [],
      1,
      0,
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      "",
      "",
      false,
      "",
    );

    let apiSecurityItems: ApiSecurityItem[] = [];
    const apiDiscoveryHelper: APIDiscoveryHelper = new APIDiscoveryHelper(Object(), "", "");
    const apiListJSON = fs.readFileSync(process.cwd() + "/tests/src/apiDiscoveryHelper/response.json", "utf8");
    apiDiscoveryHelper.extractAPIList(repo, "/home/mir/src/lambda-app", apiListJSON, apiSecurityItems);
    const apiSecurityItemsWithoutTime = apiSecurityItems.map(({ firstSeen, ...rest }) => rest);
    const expectedResult = [
      {
        servers: [],
        methodResponses: [{ code: "404" }],
        methodTags: [],
        methodParameters: [
          { in: "path", name: "item_id", required: true },
          { in: "path", name: "user_name", required: false },
        ],
        fileName: [],
        scanId: "",
        appId: "",
        appType: "",
        appName: "",
        epName: "/login_submit",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", line: 36, source: "code", snippet: "@app.post('/login_submit')", link: "test.py36" }],
        title: "name API",
        appLink: "",
      },
      {
        servers: [],
        methodResponses: [],
        methodTags: [],
        methodParameters: [],
        fileName: [],
        scanId: "",
        appId: "",
        appType: "",
        appName: "",
        epName: "/submit_order",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", line: 75, source: "code", snippet: "@app.post('/submit_order')", link: "test.py75" }],
        title: "name API",
        appLink: "",
      },
      {
        servers: [],
        methodResponses: [],
        methodTags: [],
        methodParameters: [],
        fileName: [],
        scanId: "",
        appId: "",
        appType: "",
        appName: "",
        epName: "/add_to_cart",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", line: 103, source: "code", snippet: "@app.post('/add_to_cart')", link: "test.py103" }],
        title: "name API",
        appLink: "",
      },
      {
        servers: [],
        methodResponses: [],
        methodTags: [],
        methodParameters: [],
        fileName: [],
        scanId: "",
        appId: "",
        appType: "",
        appName: "",
        epName: "/cart",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", line: 123, source: "code", snippet: "@app.post('/cart')", link: "test.py123" }],
        title: "name API",
        appLink: "",
      },
    ];
    expect(apiSecurityItemsWithoutTime).toEqual(expect.arrayContaining(expectedResult));
  });

  it("test mergeAPISecurityItems", async () => {
    const repo: Repo = new Repo(
      "id",
      "",
      "",
      "name",
      "id",
      "",
      "",
      "n",
      "",
      false,
      "",
      0,
      false,
      false,
      false,
      "",
      false,
      [],
      1,
      0,
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      0,
      "",
      "",
      "",
      "",
      "",
      "",
      false,
      "",
    );

    const apiDiscoveryHelper: APIDiscoveryHelper = new APIDiscoveryHelper(Object(), "", "");
    let apiSecurityItems: ApiSecurityItem[] = [];
    const apiListJSON = fs.readFileSync(process.cwd() + "/tests/src/apiDiscoveryHelper/response_merge.json", "utf8");
    apiDiscoveryHelper.extractAPIList(repo, "/home/mir/src/lambda-app", apiListJSON, apiSecurityItems);
    let apiSecurityItem1: ApiSecurityItem = new ApiSecurityItem();
    apiSecurityItem1.scanId = "1234";
    apiSecurityItem1.appId = "1234";
    apiSecurityItem1.epName = "/login_submit";
    apiSecurityItem1.methodName = "POST";
    apiSecurityItem1.methodResponses = [
      { code: "502", description: "502_desc" },
      { code: "404", description: " 404_desc" },
    ];
    (apiSecurityItem1.methodParameters = [
      { in: "path", name: "item_id", required: true, description: "item_id_desc" },
      { in: "path", name: "pwd", required: false, description: "pwd_desc" },
    ]),
      (apiSecurityItem1.framework = "fastapi");
    let apiSecurityItemDef: ApiSecurityItemDef = new ApiSecurityItemDef();
    apiSecurityItemDef.fileName = "test.py";
    apiSecurityItemDef.source = ApiSecurityItemSource.codeOpenApi;
    apiSecurityItem1.definitions.push(apiSecurityItemDef);
    apiSecurityItem1.function = "login_test";

    let apiSecurityItem2: ApiSecurityItem = new ApiSecurityItem();
    apiSecurityItem2.scanId = "1234";
    apiSecurityItem2.appId = "1234";
    apiSecurityItem2.epName = "/login_query";
    apiSecurityItem2.methodName = "POST";
    apiSecurityItem2.framework = "fastapi";
    apiSecurityItem2.definitions.push(apiSecurityItemDef);
    apiSecurityItem2.function = "login_query";

    apiSecurityItems.push(apiSecurityItem1);
    apiSecurityItems.push(apiSecurityItem2);
    apiSecurityItems = APIDiscoveryHelper.mergeAPISecurityItems(apiSecurityItems, "test_repo");
    const apiSecurityItemsWithoutTime = apiSecurityItems.map(({ firstSeen, ...rest }) => rest);
    const expectedResult = [
      {
        servers: [],
        methodResponses: [
          { code: "404", description: " 404_desc" },
          { code: "502", description: "502_desc" },
        ],
        methodTags: [],
        methodParameters: [
          { in: "path", name: "item_id", required: true, description: "item_id_desc" },
          { in: "path", name: "user_name", required: false },
          { in: "path", name: "pwd", required: false, description: "pwd_desc" },
        ],
        scanId: "1234",
        appId: "1234",
        appType: "",
        appName: "",
        epName: "/login_submit",
        methodName: "POST",
        framework: "fastapi",
        definitions: [
          { fileName: "test.py", line: 36, source: "code", snippet: "@app.post('/login_submit')", link: "test.py36" },
          { fileName: "test.py", source: "code_open_api" },
        ],
        function: "login_test",
        fileName: [],
        title: "name API",
        appLink: "",
      },
      {
        servers: [],
        methodResponses: [
          { code: "502", description: "502_desc" },
          { code: "404", description: " 404_desc" },
        ],
        methodTags: [],
        methodParameters: [
          { in: "path", name: "item_id", required: true, description: "item_id_desc" },
          { in: "path", name: "pwd", required: false, description: "pwd_desc" },
        ],
        scanId: "1234",
        appId: "1234",
        appType: "",
        title: "test_title",
        appName: "",
        epName: "/login_submit",
        methodName: "POST",
        framework: "fastapi",
        definitions: [
          { fileName: "test_new.py", line: 75, source: "code", snippet: "@app.post('/login_submit')", link: "test_new.py75" },
          { fileName: "test.py", source: "code_open_api" },
        ],
        description: "test_desc",
        function: "login_test",
        fileName: [],
        appLink: "",
      },
      {
        servers: [],
        methodTags: [],
        scanId: "",
        appId: "",
        appType: "",
        appName: "",
        epName: "/add_to_cart",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", line: 103, source: "code", snippet: "@app.post('/add_to_cart')", link: "test.py103" }],
        fileName: [],
        title: "name API",
        appLink: "",
        methodParameters: [{ in: "path", name: "user_name", required: false }],
        methodResponses: [{ code: "404" }, { code: "403" }],
      },
      {
        servers: [],
        methodResponses: [],
        methodTags: [],
        methodParameters: [],
        scanId: "1234",
        appId: "1234",
        epName: "/login_query",
        methodName: "POST",
        framework: "fastapi",
        definitions: [{ fileName: "test.py", source: "code_open_api" }],
        function: "login_query",
        fileName: [],
      },
    ];
    expect(apiSecurityItemsWithoutTime).toEqual(expect.arrayContaining(expectedResult));
  });
});
