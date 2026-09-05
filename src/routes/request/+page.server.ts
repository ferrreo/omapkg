import { redirect } from '@sveltejs/kit';
import { environment, field, formAction } from '$lib/server/http';
import { submitRequest } from '$lib/server/requests';
import type { Actions } from './$types';
export const actions: Actions = {
  default: (event) => formAction(event, async (form) => {
    const requestId = await submitRequest(environment(event), event.locals.actor, {
      name: field(form, 'name').trim(), description: field(form, 'description').trim(), upstream_url: field(form, 'upstream_url').trim(),
      source_kind: field(form, 'source_kind'), area: field(form, 'area'), declared_license: field(form, 'declared_license').trim()
    });
    if (event.locals.actor?.role !== 'public') redirect(303, `/maintain/requests/${requestId}`);
    return { requestId, message: 'Request received. A maintainer will review the upstream source before generation.' };
  })
};
