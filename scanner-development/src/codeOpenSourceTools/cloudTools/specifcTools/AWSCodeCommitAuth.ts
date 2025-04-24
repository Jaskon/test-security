import { RequestSigner } from "aws4";

const b64 = (str: string) => Buffer.from(str.toString(), "binary").toString("base64"),
  replace = (search: string | RegExp, substitution: string) => (str: string) => str.replace(search, substitution),
  pipe =
    (fns: ReadonlyArray<any>) =>
    (thing: string): string =>
      fns.reduce((val, fn) => fn(val), thing),
  removePadding = replace(/=+$/, "");

export interface AWSIAMCredentials {
  accessKeyId: string | undefined;
  secretAccessKey: string | undefined;
  sessionToken: string | undefined;
}

export const getBearerToken = (repoName: string, codeRegion: string, credentials: AWSIAMCredentials): string => {
  let username = credentials.accessKeyId;
  if (credentials.sessionToken) {
    username += `%${credentials.sessionToken}`;
  }

  const signer = new RequestSigner(
    {
      service: "codecommit",
      method: "GIT",
      region: codeRegion,
      host: `git-codecommit.${codeRegion}.amazonaws.com`,
      path: `/v1/repos/${repoName}`,
    },
    credentials,
  );

  const password = signer.getDateTime() + "Z" + signer.signature();

  const base64BasicToken = pipe([token => `${token}`, b64, removePadding]);
  return base64BasicToken(`${username}:${password}`);
};
