import { auth, resolver, protocol } from '@iden3/js-iden3-auth';
import { Request, Response } from 'express-serve-static-core';
import store from 'store2';
import { handleUserState } from './utils/store/handleUserState';
import getRawBody from 'raw-body';
import { requestMap, keyDIR } from './main';

// Callback verifies the proof after sign-in callbacks
export async function Callback(req: Request, res: Response) {
  // Get session ID from request
  const sessionId = req.query.sessionId;

  // get JWZ token params from the post request
  const raw = await getRawBody(req);
  const tokenStr = raw.toString().trim();

  const ethURL = process.env.RPC_URL as string;
  const contractAddress = '0x134B1BE34911E39A8397ec6289782989729807a4';

  const ethStateResolver = new resolver.EthStateResolver(
    ethURL,
    contractAddress
  );

  const resolvers = {
    ['polygon:mumbai']: ethStateResolver,
  };

  // fetch authRequest from sessionID
  const authRequest = requestMap.get(`${sessionId}`);

  // EXECUTE VERIFICATION
  const verifier = await auth.Verifier.newVerifier({
    stateResolver: resolvers,
    circuitsDir: keyDIR,
    ipfsGatewayURL: 'https://ipfs.io',
  });
  try {
    const opts = {
      acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minute
    };

    const authResponse = await verifier.fullVerify(
      tokenStr,
      authRequest.request,
      opts
    );

    requestMap.set(`${sessionId}`, {
      ...requestMap.get(`${sessionId}`),
      isAuth: true,
      identifier: authResponse.from,
    });

    const userExist = store.has(authResponse.from);
    // this method should only be used for testing/Demo purposes, user state should be handled by a db etc...
    handleUserState(userExist, authResponse, sessionId, requestMap);

    return res
      .status(200)
      .set('Content-Type', 'application/json')
      .send(
        'user with ID: ' + authResponse.from + ' Successfully authenticated'
      );
  } catch (error) {
    console.log('error', error);
    return res.status(500).send(error);
  }
}
