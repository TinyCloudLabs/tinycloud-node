export {
  createListenTranscriptCapability,
  LISTEN_CONTENT_SPACE,
  LISTEN_TRANSCRIPT_CONVERSATION_COLUMNS,
  LISTEN_TRANSCRIPT_PARTICIPANT_COLUMNS,
  LISTEN_TRANSCRIPT_RESOURCE_TYPE,
  LISTEN_TRANSCRIPT_SQL_STATEMENT_TEMPLATES,
  listenTranscriptResourceId,
} from "../packages/client/src/transcript-binding";

export function resolveManifestPermissionPath(
  manifest: { app_id?: string },
  _service: string,
  path: string,
): string {
  const appId = manifest.app_id ?? "xyz.tinycloud.listen";
  if (path === "/" || path.length === 0) return `${appId}/`;
  return `${appId}/${path.replace(/^\/+/, "")}`;
}

export type ApiClient = {
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body?: unknown): Promise<T>;
  del<T>(path: string): Promise<T>;
};
