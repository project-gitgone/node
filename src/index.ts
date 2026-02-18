import crypto from "node:crypto";

export interface GitGoneOptions {
  token?: string;
  serverUrl?: string;
  /** @default true */
  populateProcessEnv?: boolean;
  /** @default false */
  override?: boolean;
}

interface SecretResponse {
  encryptedProjectKey: string;
  secrets: {
    ciphertext: string;
    iv: string;
    authTag: string;
  };
}

export class GitGone {
  private _env: Record<string, string> = {};
  private _isInitialized = false;

  async config(options: GitGoneOptions = {}): Promise<Record<string, string>> {
    const token = options.token || process.env.GITGONE_TOKEN;
    const serverUrl =
      options.serverUrl ||
      process.env.GITGONE_SERVER_URL ||
      "http://localhost:3333";
    const populate = options.populateProcessEnv ?? true;
    const override = options.override ?? false;

    if (!token) {
      throw new Error(
        "[GitGone] Missing token. Set GITGONE_TOKEN or pass it to config().",
      );
    }

    const [, tokenSecret] = token.split(".");
    if (!tokenSecret) {
      throw new Error(
        '[GitGone] Invalid token format. Expected "ptok_ID.Secret"',
      );
    }

    try {
      const response = await fetch(`${serverUrl}/api/secrets/token`, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        const errorData = (await response.json().catch(() => ({}))) as Record<
          string,
          any
        >;
        throw new Error(errorData.message || response.statusText);
      }

      const data = (await response.json()) as SecretResponse;

      const projectKey = this.decrypt(data.encryptedProjectKey, tokenSecret);
      const rawSecrets = this.decrypt(
        `${data.secrets.iv}:${data.secrets.authTag}:${data.secrets.ciphertext}`,
        projectKey,
      );

      this._env = this.parseEnv(rawSecrets);
      this._isInitialized = true;

      if (populate) {
        for (const key in this._env) {
          if (override || !process.env[key]) {
            process.env[key] = this._env[key];
          }
        }
      }

      return this._env;
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`[GitGone] Initialization failed: ${message}`);
    }
  }

  get(key: string): string | undefined {
    if (!this._isInitialized) {
      console.warn(`[GitGone] Warning: Accessing "${key}" before config().`);
    }
    return this._env[key];
  }

  private parseEnv(content: string): Record<string, string> {
    const result: Record<string, string> = {};
    const lines = content.split(/\r?\n/);

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const separatorIndex = trimmed.indexOf("=");
      if (separatorIndex === -1) continue;

      const key = trimmed.slice(0, separatorIndex).trim();
      let value = trimmed.slice(separatorIndex + 1).trim();

      const commentIndex = value.indexOf(" #");
      if (commentIndex !== -1) {
        value = value.slice(0, commentIndex).trim();
      }

      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }

      result[key] = value;
    }

    return result;
  }

  private decrypt(bundle: string, secret: string): string {
    const [ivHex, authTagHex, encryptedHex] = bundle.includes(":")
      ? bundle.split(":")
      : ["", "", ""];

    if (!ivHex || !authTagHex || !encryptedHex) {
      throw new Error("[GitGone] Malformed encrypted data bundle.");
    }

    const key = crypto.createHash("sha256").update(secret).digest();
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(ivHex, "hex"),
    );

    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

    let decrypted = decipher.update(encryptedHex, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }

  get parsed() {
    return this._env;
  }
}

export const gitgone = new GitGone();
export default gitgone;
