'use strict';

var Fastify = require('fastify');
var jwtAuthz = require('./fastify-jwt-authz');

test('should decorate request instance with jwtAuthz method', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get('/test', function (request, reply) {
    expect(request).toHaveProperty('jwtAuthz');
    return { foo: 'bar' };
  });

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test',
  });

  expect(res.statusCode).toBe(200);
});

test('should throw an error "Scopes cannot be empty" with an empty scopes parameter', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get(
    '/test2',
    {
      preHandler: function (request, reply, done) {
        request.jwtAuthz([], done);
      },
    },
    function (request, reply) {
      return { foo: 'bar' };
    }
  );

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test2',
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().message).toBe('Scopes cannot be empty');
});

test('should throw an error "request.user does not exist" non existing request.user', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get(
    '/test3',
    {
      preHandler: function (request, reply, done) {
        request.jwtAuthz('baz', done);
      },
    },
    function (request, reply) {
      return { foo: 'bar' };
    }
  );

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test3',
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().message).toBe('request.user does not exist');
});

test('should throw an error "request.user.scope must be a string"', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get(
    '/test4',
    {
      preHandler: function (request, reply, done) {
        request.user = {
          name: 'sample',
          scope: 123,
        };
        request.jwtAuthz('baz', done);
      },
    },
    function (request, reply) {
      return { foo: 'bar' };
    }
  );

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test4',
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().message).toBe('request.user.scope must be a string');
});

test('should throw an error "Insufficient scope"', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get(
    '/test5',
    {
      preHandler: function (request, reply, done) {
        request.user = {
          name: 'sample',
          scope: 'baz',
        };
        request.jwtAuthz(['foo'], done);
      },
    },
    function (request, reply) {
      request
        .jwtAuthz(['foo'])
        .catch(err => t.match(err.message, 'Insufficient scope'));

      reply.send({ foo: 'bar' });
    }
  );

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test5',
  });

  expect(res.statusCode).toBe(500);
  expect(res.json().message).toBe('Insufficient scope');
});

test('should verify user scope', async function () {
  const fastify = Fastify();
  fastify.register(jwtAuthz);

  fastify.get(
    '/test6',
    {
      preHandler: function (request, reply, done) {
        request.user = {
          name: 'sample',
          scope: 'user manager',
        };
        request.jwtAuthz(['user'], done);
      },
    },
    function (request, reply) {
      return { foo: 'bar' };
    }
  );

  fastify.listen({ port: 0 }, function (err) {
    fastify.server.unref();
  });

  const res = await fastify.inject({
    method: 'GET',
    url: '/test6',
  });

  expect(res.statusCode).toBe(200);
  expect(res.json()).toEqual({ foo: 'bar' });
});
