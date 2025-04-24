class IpupSub {
  uuid: string;
  redisClient: any;
  orgName: string;

  init() {}
  sendPupSubMessage(info: any) {
    return null;
  }
  createPupSubListener() {}
  closeConnection() {}

  constructor(uuid: string, orgName: string) {
    this.uuid = uuid;
    this.orgName = orgName;
  }
}

export default IpupSub;
