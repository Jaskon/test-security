import { Topic } from "../../../entitis/codeRepoTypes";
import loggerImport from "../../../logger";
import StatesHelper from "../../statesHelper";
import { ServiceBase } from "../serviceBase";
import { addTags, deleteTags, getAllTags, GetAppTagsAndExclusions, modifyAppsTags, resetOxTags } from "./tags-service.gql";
import { GetAppsTagsAndExclusionsResponse } from "./tags-service.types";

const logger = loggerImport.getDebugLogger();
const TAGS_SERVICE_HOST_URL = process.env.TAGS_SERVICE_HOST_URL || "missing tags service host url";

export class TagsService extends ServiceBase {
  constructor() {
    super(TAGS_SERVICE_HOST_URL);
  }

  private static _instance: TagsService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getAppTagsAndExclusions(orgId: string, appId: string) {
    try {
      await this.setAuthHeader();

      const variables = {
        orgId,
        input: {
          appId,
        },
        getAppsTagsInput2: {
          appsIds: appId,
        },
      };

      const res = await this.gqlClient.request<GetAppsTagsAndExclusionsResponse>(GetAppTagsAndExclusions, variables);
      const { tagsIds } = res.getAppTagsExclusion;
      const { appsTags } = res.getAppsTags;
      const tags = appsTags
        .filter(i => i.appliedBy !== "support@ox.security")
        .map(i => {
          return { ...i.tag, appliedBy: i.appliedBy };
        });
      for (const tag of tags) {
      }
      return {
        excludedTagsIds: tagsIds,
        tags,
      };
    } catch (e) {
      logger.error(`failed to getAppTagsAndExclusions. appId: ${appId}. error: ${e}`);
    }
    return {
      excludedTagsIds: [],
      tags: [],
    };
  }

  async resetOxTags(orgId: string, oxAppsTags: Map<string, string[]>) {
    try {
      await this.setAuthHeader();

      const input: { tagId: string; appsIds: string[] }[] = [];
      oxAppsTags.forEach((appsIds, tagId) => {
        input.push({ tagId, appsIds });
      });
      const variables = {
        orgId,
        input,
      };
      await this.gqlClient.request(resetOxTags, variables);
      return true;
    } catch (e) {
      logger.error(`failed to resetOxTags`, e);
      return false;
    }
  }

  async getAllTags() {
    try {
      await this.setAuthHeader();

      const variables = {
        orgId: StatesHelper.Instance.orgName,
      };

      const res = await this.gqlClient.request(getAllTags, variables);
      return res.getAllTags.tags || [];
    } catch (e) {
      logger.error(`failed to getAllTags`, e);
      return false;
    }
  }

  async addTopicAsTags(topics: Topic[]) {
    try {
      await this.setAuthHeader();
      const input = { tagsInput: [] };
      input.tagsInput = topics.map(topic => {
        return {
          displayName: topic.displayName,
          isOxTag: topic.isOxTag,
          name: topic.name,
          parentTagId: null,
          tagType: topic.tagType,
          isGithubTopicTag: true,
          tagCategory: "topic",
        };
      });

      const variables = {
        orgId: StatesHelper.Instance.orgName,
        input,
      };
      const res = await this.gqlClient.request(addTags, variables);
      return res;
    } catch (e) {
      logger.error(`failed to addTopicAsTags`, e);
      return false;
    }
  }

  async modifyAppsTags(appIds: string[], addedTagsIds: string[], removedTagsIds: string[]) {
    try {
      await this.setAuthHeader();

      const input = { appIds, addedTagsIds, removedTagsIds };

      const variables = {
        orgId: StatesHelper.Instance.orgName,
        input,
      };
      await this.gqlClient.request(modifyAppsTags, variables);
      return true;
    } catch (e) {
      logger.error(`failed to modifyAppsTags, error: ${e}`);
      return false;
    }
  }
}
