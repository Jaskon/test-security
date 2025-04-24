export interface OrgSbom {
  scanId: string;
  scanDate: Date;
  sbom: string; // compressed
  sbomCsv: string; // compressed
}
