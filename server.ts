import { serve } from "bun";
import { pbkdf2Sync, randomBytes, createCipheriv } from "node:crypto";
import { readFile, writeFile, mkdir, access } from "node:fs/promises";
import path from "node:path";

const config = await readFile("./config.json", "utf-8").then(JSON.parse);
const { port, savePath, iterations } = config;

await mkdir(savePath, { recursive: true });

console.log(`Server is running at http://0.0.0.0:${port}`);

serve({
  port: port,
  hostname: "0.0.0.0",
  async fetch(req) {
    if (req.method === "GET") {
      return new Response(Bun.file("index.html"), {
        headers: { "Content-Type": "text/html" },
      });
    }

    if (req.method === "POST" && req.url.endsWith("/encrypt")) {
      try {
        const formData = await req.formData();
        const password = formData.get("password") as string;
        const mediaType = formData.get("mediaType") as string;
        const content = formData.get("content");
        const userFilename = formData.get("filename") as string;

        if (!password) {
          return new Response(JSON.stringify({ success: false, msg: "Password is required." }), { status: 400 });
        }
        if (!userFilename) {
          return new Response(JSON.stringify({ success: false, msg: "Filename is required." }), { status: 400 });
        }

        const finalFileName = `${userFilename}.enc`;
        const resolvedBase = path.resolve(savePath);
        const fullPath = path.resolve(resolvedBase, finalFileName);

        // Path containment validation
        const relative = path.relative(resolvedBase, fullPath);
        const isSafe = relative && !relative.startsWith("..") && !path.isAbsolute(relative);
        if (!isSafe) {
          return new Response(JSON.stringify({ success: false, msg: "Invalid filename path." }), { status: 400 });
        }

        if (await Bun.file(fullPath).exists()) {
          return new Response(JSON.stringify({ success: false, msg: "File already exists." }), { status: 409 });
        }

        const salt = randomBytes(8);
        const keyIv = pbkdf2Sync(password, salt, iterations, 48, "sha256");
        const key = keyIv.subarray(0, 32);
        const iv = keyIv.subarray(32, 48);

        const cipher = createCipheriv("aes-256-cbc", key, iv);

        let plaintext: Buffer;
        if (content instanceof File) {
          plaintext = Buffer.from(await content.arrayBuffer());
        } else {
          plaintext = Buffer.from(content as string, "utf-8");
        }

        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

        const finalBuffer = Buffer.concat([
          Buffer.from("Salted__"),
          salt,
          ciphertext
        ]);

        await mkdir(path.dirname(fullPath), { recursive: true });
        await writeFile(fullPath, finalBuffer);

        return new Response(JSON.stringify({ success: true, msg: `Saved successfully: ${finalFileName}` }));
      } catch (e) {
        return new Response(JSON.stringify({ success: false, msg: "Server error occurred" }), { status: 500 });
      }
    }

    return new Response("Not Found", { status: 404 });
  },
});
