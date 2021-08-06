import {OAuth2Client} from './oauth2client';

export class SingleTokenClient extends OAuth2Client {
    constructor(accessToken: string) {
        super();
        this.setCredentials({access_token: accessToken});
    }

    fromJSON(): void {
        throw new Error('Method not implemented');
    }
}
