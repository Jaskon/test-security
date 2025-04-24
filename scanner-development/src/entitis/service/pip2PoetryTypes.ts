export interface CliToolsImage {
  queueName: string;
  queueKey: string;
}

export interface Pip2PoetryTypesResponse {
  ignoreTools: string[];
  snykImages: CliToolsImage[];
}
