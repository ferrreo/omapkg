import type { InputObject } from './frozen-inputs';

type CaptureRequest = {
  operation?: 'start' | 'complete'; size?: number; uploadId?: string;
  revisionId?: string; reason?: string; bundle?: InputObject; lock?: InputObject;
  capture?: InputObject; importId?: string; sourceId?: string;
};

export async function postCaptureRequest<T>(path: string, input: CaptureRequest): Promise<T> {
  const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) });
  const result: T = await response.json();

  if (!response.ok) throw new Error(response.statusText || 'Capture upload failed.');

  return result;
}

export async function uploadCaptureObjects(files: FileList | undefined, progress: (value: { completed: number; total: number; message: string }) => void) {
  const objects = Array.from(files ?? []).filter((file) => /^[^/]+\/objects\/[a-f0-9]{64}$/.test(file.webkitRelativePath));

  if (!objects.length || objects.length > 32768 || new Set(objects.map((file) => file.name)).size !== objects.length) throw new Error('Capture objects are missing, duplicated or exceed the upload limit.');
  const total = objects.reduce((bytes, file) => bytes + file.size, 0); let completed = 0;

  for (const [index, file] of objects.entries()) {
    const path = `/api/maintain/inputs/objects/${file.name}`;
    progress({ completed, total, message: `Retaining object ${index + 1} of ${objects.length}.` });
    const started = await postCaptureRequest<{ completed?: InputObject; partSize: number; uploadId: string; parts: { part_number: number }[] }>(path, { operation: 'start', size: file.size });

    if (!started.completed) {
      if (started.partSize !== 8 * 1024 * 1024 || !started.uploadId || !Array.isArray(started.parts)) throw new Error('Invalid input upload response.');
      const saved = new Set(started.parts.map((part) => part.part_number));

      for (let offset = 0, part = 1; offset < file.size; offset += started.partSize, part++) {
        if (saved.has(part)) continue;
        const response = await fetch(`${path}?uploadId=${encodeURIComponent(started.uploadId)}&part=${part}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: file.slice(offset, offset + started.partSize) });

        const result: { error?: string } = await response.json();

        if (!response.ok) throw new Error(result.error ?? 'Input part upload failed.');
      }

      progress({ completed, total, message: `Verifying object ${index + 1} of ${objects.length}.` });
      await postCaptureRequest(path, { operation: 'complete', uploadId: started.uploadId });
    }

    completed += file.size;
    progress({ completed, total, message: `Retained object ${index + 1} of ${objects.length}.` });
  }
}
