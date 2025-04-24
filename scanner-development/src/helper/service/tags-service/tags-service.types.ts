import { IOxTag, OxTagCategory, OxTagId, OxTagType } from "@oxappsec/ox-consolidated-tags";

export interface GetAppsTagsAndExclusionsResponse {
  getAppTagsExclusion: {
    tagsIds: OxTagId[];
  };
  getAppsTags: {
    appsTags: [
      {
        tagType: OxTagType;
        appId: string;
        tagId: string;
        isOxTag: true;
        appliedBy: string;
        tag: IOxTag;
        tagCategory: OxTagCategory;
      },
    ];
  };
}
