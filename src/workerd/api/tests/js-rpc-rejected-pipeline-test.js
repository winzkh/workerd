// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
import assert from 'node:assert';
import { RpcTarget } from 'cloudflare:workers';

// Keeps rejected promises reachable so that GC cannot release their pipelines
// and hide a pipeline that the runtime failed to drop.
const held = [];

class Step extends RpcTarget {
  async fail() {
    throw new Error('step failed');
  }

  async retry(callback) {
    const first = callback();
    held.push(first);
    await assert.rejects(first, { message: 'first attempt fails' });
    return await callback();
  }
}

// Polls the tail worker while this test stays alive and keeps holding its rejected promises.
// A pinned pipeline leaves the callee with nothing to wait on, so it is aborted as hung.
async function assertCalleeSucceeded(env, method) {
  for (let i = 0; i < 1000; i++) {
    const result = await env.RESULTS.outcome(method);
    if (result !== undefined) {
      assert.deepStrictEqual(result, { outcome: 'ok', exceptions: [] });
      return;
    }
    await scheduler.wait(10);
  }
  assert.fail(`no tail event for ${method}`);
}

export const callerHoldsRejectedCall = {
  async test(ctrl, env) {
    const promise = env.CALLEE.throwsDirectly();
    held.push(promise);
    await assert.rejects(promise, { message: 'boom from callee' });
    await assertCalleeSucceeded(env, 'throwsDirectly');

    // Pipelining on the rejected promise reports the call's error, both when
    // awaiting a property and when calling a method through it.
    await assert.rejects(Promise.resolve(promise.foo), {
      message: 'boom from callee',
    });
    await assert.rejects(promise.foo.bar(), { message: 'boom from callee' });
  },
};

export const callerHoldsRejectedActorCall = {
  async test(ctrl, env) {
    const actor = env.ACTOR.get(env.ACTOR.idFromName('actor'));
    const promise = actor.actorThrowsDirectly();
    held.push(promise);
    await assert.rejects(promise, { message: 'boom from actor' });
    await assertCalleeSucceeded(env, 'actorThrowsDirectly');
    await assert.rejects(promise.foo.bar(), { message: 'boom from actor' });
  },
};

export const calleeHoldsRejectedCallOnCallerStub = {
  async test(ctrl, env) {
    assert.strictEqual(await env.CALLEE.rejectsOnCallerStub(new Step()), 'ok');
    await assertCalleeSucceeded(env, 'rejectsOnCallerStub');
  },
};

export const callerHoldsRejectedCallback = {
  async test(ctrl, env) {
    assert.strictEqual(await env.CALLEE.retriesCallback(new Step()), 'ok');
    await assertCalleeSucceeded(env, 'retriesCallback');
  },
};
