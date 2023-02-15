import { DoneFuncWithErrOrRes, FastifyPluginCallback } from 'fastify';

export interface jwtAuthz {
  (scopes: string | string[], callback: DoneFuncWithErrOrRes): Promise<void>;
}

declare module 'fastify' {
  interface FastifyRequest {
    jwtAuthz: jwtAuthz;
  }
}

export const fastifyJwtAuthz: FastifyPluginCallback;
export default fastifyJwtAuthz;
