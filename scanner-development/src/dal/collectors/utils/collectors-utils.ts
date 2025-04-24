export const findLineNumberAndText = (content: string, lineNumber: number) => {
  const lines: string[] = content.split(/\r?\n/);
  if (lineNumber > 0) {
    const lineText: string = lines[lineNumber - 1] || "";
    return lineText?.replace(/^\s+/, "");
  }
  return "";
};

export const removeSlashFromUrl = (url: string) => {
  if (url.endsWith("/")) {
    const i = url.lastIndexOf("/");
    return url.substring(0, i);
  }
  return url;
};
