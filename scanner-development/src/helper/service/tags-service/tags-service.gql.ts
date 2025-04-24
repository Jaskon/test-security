import { gql } from "graphql-request";

export const GetAppTagsAndExclusions = gql`
  query GetAppTagsExclusionAndTags($orgId: String, $input: GetAppTagsExclusionInput!, $getAppsTagsInput2: GetAppsTagsInput!) {
    getAppTagsExclusion(orgId: $orgId, input: $input) {
      tagsIds
    }
    getAppsTags(orgId: $orgId, input: $getAppsTagsInput2) {
      appsTags {
        tagType
        appId
        tagId
        isOxTag
        appliedBy
        tag {
          tagId
          name
          displayName
          tagType
          createdBy
          isOxTag
          createdAt
          updatedAt
          isGithubTopicTag
        }
      }
    }
  }
`;

export const resetOxTags = gql`
  mutation ResetOxTags($orgId: String, $input: [ResetOxTagsInput!]!) {
    resetOxTags(orgId: $orgId, input: $input) {
      acknowledge
    }
  }
`;

export const addTags = gql`
  mutation AddTags($input: AddTagInput!) {
    addTags(input: $input) {
      tags {
        tagId
      }
    }
  }
`;

export const modifyAppsTags = gql`
  mutation ModifyAppsTags($input: ModifyAppsTagsInput!) {
    modifyAppsTags(input: $input) {
      acknowledge
    }
  }
`;

export const getAllTags = gql`
  query GetAllsTags {
    getAllTags {
      tags {
        tagId
        name
        displayName
        tagType
        createdBy
        isOxTag
        createdAt
        updatedAt
        isGithubTopicTag
      }
    }
  }
`;

export const deleteTags = gql`
  mutation DeleteTags($input: DeleteTagInput!) {
    deleteTags(input: $input) {
      acknowledge
    }
  }
`;
