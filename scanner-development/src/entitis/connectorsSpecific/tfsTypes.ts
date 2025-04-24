export declare namespace TFS2018Types {
  export interface Projects {
    id: string;
    name: string;
    description?: string;
    url: string;
    state: string;
    revision: number;
    visibility: string; //"private"
    collectionName?: string;
  }

  export interface Identities {
    identity: Identity;
  }

  export interface Identity {
    displayName: string;
    url: string;
    id: string;
    uniqueName: string;
    imageUrl: string;
    isContainer?: boolean;
  }
}
