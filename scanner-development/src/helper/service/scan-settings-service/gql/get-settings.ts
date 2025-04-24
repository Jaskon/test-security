import { gql } from "graphql-request";
export const getSettings = gql`
  query GetSettings($orgId: String) {
    getSettings(orgId: $orgId) {
      settings {
        enabled
        configured
        settingsType
        settingsSubType
        valueList
        id
        inputText
        subSettings {
          settings {
            inputText
            idSubSetting
          }
        }
      }
    }
  }
`;
