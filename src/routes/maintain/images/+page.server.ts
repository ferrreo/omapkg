import { getBuildImages, registerBuildImage, setBuildImageEnabled, setDefaultBuildImage } from '$lib/server/build-images';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  return { images: await getBuildImages(environment(event)) };
};

export const actions: Actions = {
  register: (event) => formAction(event, async (form) => registerBuildImage(environment(event), event.locals.actor, {
    label: field(form, 'label'),
    image_ref: field(form, 'image_ref'),
    architecture: field(form, 'architecture'),
    mirror: field(form, 'mirror'),
  })),
  enable: (event) => formAction(event, async (form) => setBuildImageEnabled(environment(event), event.locals.actor, field(form, 'image_id'), true)),
  disable: (event) => formAction(event, async (form) => setBuildImageEnabled(environment(event), event.locals.actor, field(form, 'image_id'), false)),
  setDefault: (event) => formAction(event, async (form) => setDefaultBuildImage(environment(event), event.locals.actor, field(form, 'image_id'))),
};
