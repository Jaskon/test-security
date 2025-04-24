import { isDevelopment, isLocalDevelopment } from "../envUtils";
import { AtlasIndexFormat } from "./searchIndexTypes";

//add collection name to below if search index needs to be created for the collection
export const SearchIndexCollections = () => {
  const collections = [];
  if (!isDevelopment() && !isLocalDevelopment()) {
    collections.push("current-issues");
  }
  //returning empty so as to not create any indexes if not found for now in all envs -- TODO: whole code block to be removed later
  return [];
};

export const CurrentIssuesIndexes: AtlasIndexFormat[] = [
  {
    collectionName: "current-issues",
    indexName: "filter",
    index: {
      analyzer: "lucene.keyword",
      searchAnalyzer: "lucene.keyword",
      mappings: {
        dynamic: false,
        fields: {
          aggItems: {
            fields: {
              filePath: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 20,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
              ],
              image: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 20,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
              ],
              language: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
          allUniqueLibs: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 20,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          appBp: [
            {
              type: "sortableNumberBetaV1",
            },
            {
              type: "number",
            },
          ],
          appId: {
            analyzer: "lucene.keyword",
            searchAnalyzer: "lucene.keyword",
            type: "string",
          },
          appName: [
            {
              type: "sortableStringBetaV1",
            },
            {
              analyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 20,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          cat: [
            {
              type: "sortableStringBetaV1",
            },
            {
              type: "string",
            },
          ],
          categoryId: [
            {
              representation: "int64",
              type: "numberFacet",
            },
            {
              representation: "int64",
              type: "number",
            },
          ],
          compliance: {
            fields: {
              control: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
              standard: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
          createdAt: [
            {
              type: "sortableDateBetaV1",
            },
            {
              type: "date",
            },
          ],
          cweList: {
            fields: {
              name: [
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 20,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
          excludedByAlert: {
            type: "boolean",
          },
          excludedByApp: {
            type: "boolean",
          },
          excludedByPolicy: {
            type: "boolean",
          },
          fixes: {
            dynamic: true,
            type: "document",
          },
          issueActions: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          issueId: [
            {
              type: "sortableStringBetaV1",
            },
            {
              type: "string",
            },
          ],
          issueOwners: {
            fields: {
              name: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 20,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
                {
                  type: "sortableStringBetaV1",
                },
              ],
            },
            type: "document",
          },
          mainTitle: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              type: "sortableStringBetaV1",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 20,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          originalToolSeverity: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          oscarData: {
            fields: {
              name: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
          pId: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          pName: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          scaVulnerabilities: {
            fields: {
              cve: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 20,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
              ],
              language: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
          scanId: {
            analyzer: "lucene.keyword",
            searchAnalyzer: "lucene.keyword",
            type: "string",
          },
          severity: [
            {
              representation: "int64",
              type: "number",
            },
            {
              type: "numberFacet",
            },
            {
              type: "sortableNumberBetaV1",
            },
          ],
          severityChange: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          severityChangedReason: {
            fields: {
              changePlusReasonFacet: [
                {
                  type: "stringFacet",
                },
              ],
              shortName: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
              ],
            },
            type: "document",
          },
          sources: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          tags: {
            fields: {
              displayName: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "keywordLowerer",
                  foldDiacritics: false,
                  maxGrams: 10,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
              ],
            },
            type: "document",
          },
          updated: {
            type: "date",
          },
        },
      },
      analyzers: [
        {
          name: "keywordLowerer",
          tokenFilters: [
            {
              type: "lowercase",
            },
          ],
          tokenizer: {
            type: "keyword",
          },
        },
      ],
    },
    action: "create",
  },
];

export const SbomIndexes: AtlasIndexFormat[] = [
  {
    collectionName: "sboms",
    indexName: "filter",
    index: {
      analyzer: "lucene.keyword",
      searchAnalyzer: "lucene.keyword",
      mappings: {
        dynamic: false,
        fields: {
          appName: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 15,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          copyWriteInfo: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 15,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          dependencyType: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          language: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          libForSearch: {
            analyzer: "keywordLowerer",
            foldDiacritics: false,
            maxGrams: 15,
            minGrams: 1,
            tokenization: "nGram",
            type: "autocomplete",
          },
          libraryName: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 15,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          libraryVersion: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 8,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          licenses: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          packageInfo: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          pkgManager: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          pkgName: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
            {
              analyzer: "keywordLowerer",
              foldDiacritics: false,
              maxGrams: 15,
              minGrams: 1,
              tokenization: "nGram",
              type: "autocomplete",
            },
          ],
          scanId: {
            analyzer: "lucene.keyword",
            searchAnalyzer: "lucene.keyword",
            type: "string",
          },
          source: [
            {
              analyzer: "lucene.keyword",
              searchAnalyzer: "lucene.keyword",
              type: "string",
            },
            {
              type: "stringFacet",
            },
          ],
          vulnerabilities: {
            fields: {
              cve: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
                {
                  analyzer: "lucene.keyword",
                  foldDiacritics: false,
                  maxGrams: 10,
                  minGrams: 1,
                  tokenization: "nGram",
                  type: "autocomplete",
                },
              ],
            },
            type: "document",
          },
          vulnerabilityCountsArr: {
            fields: {
              severity: [
                {
                  analyzer: "lucene.keyword",
                  searchAnalyzer: "lucene.keyword",
                  type: "string",
                },
                {
                  type: "stringFacet",
                },
              ],
            },
            type: "document",
          },
        },
      },
      analyzers: [
        {
          name: "keywordLowerer",
          tokenFilters: [
            {
              type: "lowercase",
            },
          ],
          tokenizer: {
            type: "keyword",
          },
        },
      ],
    },
    action: "create",
  },
];
