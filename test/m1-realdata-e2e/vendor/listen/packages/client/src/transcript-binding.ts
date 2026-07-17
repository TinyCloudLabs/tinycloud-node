export const LISTEN_RESOURCE_PREFIX = "xyz.tinycloud.listen";
export const LISTEN_CONTENT_SPACE = "applications";
export const LISTEN_CONVERSATIONS_SQL_PATH = `${LISTEN_RESOURCE_PREFIX}/conversations`;
export const LISTEN_TRANSCRIPT_RESOURCE_TYPE = `${LISTEN_RESOURCE_PREFIX}/transcript/v0`;

export const LISTEN_TRANSCRIPT_CONVERSATION_COLUMNS = [
  "id",
  "title",
  "source",
  "source_id",
  "source_url",
  "started_at",
  "ended_at",
  "duration_secs",
  "summary",
  "metadata",
  "transcript_json",
  "transcript_text",
  "created_at",
  "updated_at",
] as const;

export const LISTEN_TRANSCRIPT_PARTICIPANT_COLUMNS = [
  "id",
  "name",
  "email",
  "speaker_label",
] as const;

export const LISTEN_TRANSCRIPT_STATEMENT_NAMES = [
  "listen.getConversation",
  "listen.listParticipants",
] as const;

export type ListenTranscriptStatementName = (typeof LISTEN_TRANSCRIPT_STATEMENT_NAMES)[number];

export interface SqlFixedParam {
  index: number;
  value: unknown;
}

export interface ListenTranscriptSqlStatementTemplate {
  name: ListenTranscriptStatementName;
  sql: string;
}

export interface ListenTranscriptSqlStatement extends ListenTranscriptSqlStatementTemplate {
  fixedParams: SqlFixedParam[];
}

export interface SqlConstrainedStatementCaveat {
  mode: "constrained-statements";
  readOnly: true;
  statements: ListenTranscriptSqlStatement[];
}

export interface ListenTranscriptSqlCapability {
  service: "tinycloud.sql";
  space: string;
  path: typeof LISTEN_CONVERSATIONS_SQL_PATH;
  actions: ["tinycloud.sql/read"];
  caveats: SqlConstrainedStatementCaveat;
}

export interface ListenTranscriptSqlInvokeRequest {
  action: "executeStatement";
  name: ListenTranscriptStatementName;
  params: [];
}

export const LISTEN_TRANSCRIPT_SQL_STATEMENT_TEMPLATES: readonly ListenTranscriptSqlStatementTemplate[] =
  [
    {
      name: "listen.getConversation",
      sql: `SELECT ${LISTEN_TRANSCRIPT_CONVERSATION_COLUMNS.join(
        ", ",
      )} FROM conversation WHERE id = ?`,
    },
    {
      name: "listen.listParticipants",
      sql: `SELECT ${LISTEN_TRANSCRIPT_PARTICIPANT_COLUMNS.join(
        ", ",
      )} FROM participant WHERE conversation_id = ? ORDER BY COALESCE(speaker_label, name), id`,
    },
  ];

export function listenTranscriptResourceId(conversationId: string): string {
  if (conversationId.length === 0) {
    throw new Error("conversationId is required");
  }
  return `${LISTEN_RESOURCE_PREFIX}/transcript/${encodeURIComponent(conversationId)}`;
}

export function createListenTranscriptCapability(
  conversationId: string,
  options: { space?: string } = {},
): ListenTranscriptSqlCapability {
  const fixedConversationParam = (): SqlFixedParam[] => [{ index: 0, value: conversationId }];

  return {
    service: "tinycloud.sql",
    space: options.space ?? LISTEN_CONTENT_SPACE,
    path: LISTEN_CONVERSATIONS_SQL_PATH,
    actions: ["tinycloud.sql/read"],
    caveats: {
      mode: "constrained-statements",
      readOnly: true,
      statements: LISTEN_TRANSCRIPT_SQL_STATEMENT_TEMPLATES.map((statement) => ({
        ...statement,
        fixedParams: fixedConversationParam(),
      })),
    },
  };
}

export function listenTranscriptSqlInvokeRequests(): ListenTranscriptSqlInvokeRequest[] {
  return LISTEN_TRANSCRIPT_STATEMENT_NAMES.map((name) => ({
    action: "executeStatement",
    name,
    params: [],
  }));
}
