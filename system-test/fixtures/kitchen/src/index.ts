import {GoogleAuth, JWT} from 'google-auth-library';
// uncomment the line below during development
// import {GoogleAuth} from '../../../../build/src/index';
const jwt = new JWT();
const auth = new GoogleAuth();
async function getToken() {
  const token = await jwt.getToken('token');
  const projectId = await auth.getProjectId();
  const creds = await auth.getApplicationDefault();
  return token;
}
getToken();
