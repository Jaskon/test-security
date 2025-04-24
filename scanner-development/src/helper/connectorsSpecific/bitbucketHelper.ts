import loggerImport from "../../logger";
import axios from "axios";

const logger = loggerImport.getDebugLogger();

export const per_page_max_res = 100;
export const max_pages = 100;
export const retry_count = 4;
export const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 3;
export class BitbucketRequest {
  query: any;
  maxPage: number;
}

export const axiosCall = async (r: BitbucketRequest) => {
  const query = r.query;
  const instance = axios.get(r.query.url, { headers: { ...r.query.headers } });
  const res: any = await instance;
  return res.data;
};
