import { json, type RequestHandler } from '@sveltejs/kit';
import { uploadFactoryImagePart, FACTORY_IMAGE_UPLOAD_PART_SIZE } from '$lib/server/factory-image-run';
import { authenticateWorker, readBody, WorkerProtocolError, workerRouteFailure } from '$lib/server/workers';

export const PUT: RequestHandler = async (event) => {
  try {
    const env = event.platform?.env;

    if (!env) throw new WorkerProtocolError(503, 'Worker protocol unavailable');
    const leaseTokens = event.url.searchParams.getAll('leaseToken');

    if (leaseTokens.length !== 1 || !event.params.id || !event.params.uploadId || !event.params.partNumber) throw new WorkerProtocolError(400, 'Invalid private image upload path');
    const partNumber = Number(event.params.partNumber);

    if (!Number.isSafeInteger(partNumber)) throw new WorkerProtocolError(400, 'Invalid private image upload part number');
    const body = await readBody(event.request, FACTORY_IMAGE_UPLOAD_PART_SIZE);
    const auth = await authenticateWorker(env.DB, event.request, event.url.pathname + event.url.search, body);

    return json(await uploadFactoryImagePart(env, auth.worker, event.params.id, event.params.uploadId, partNumber, leaseTokens[0], body));
  } catch (cause) { return workerRouteFailure(cause); }
};
