import {GoogleAuth} from 'google-auth-library';
// uncomment the line below during development
// import {GoogleAuth} from '../../../../build/src/index';
const auth = new GoogleAuth();
const jwt = new auth.JWT();
async function getToken() {
  const token = await jwt.getToken('token');
  const projectId = await auth.getDefaultProjectId();
  const creds = await auth.getApplicationDefault();
  return token;
}
getToken();
