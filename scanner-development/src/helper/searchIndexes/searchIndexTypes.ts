export interface AtlasIndexFormat {
  collectionName: string;
  indexName: string;
  index: any;
  action: "create" | "update";
}

export interface SearchIndexPayload {
  analyzer: string;
  analyzers: any;
  collectionName: string;
  database: string;
  mappings: any;
  name: string;
  searchAnalyzer: string;
}
