import express from "express";
import path from "path";
import fs from "fs";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import cors from "cors";
import dotenv from "dotenv";

/**
 * 生成自定义的 UUID
 * @param pattern
 * @param charset
 */
const generateUUID = (
  pattern: string = "xxxx-xxxx-xxxx-xxxx-xxxx",
  charset: string = "abcdefghijklmnopqrstuvwxyz0123456789"
): string =>
  pattern.replace(
    /[x]/g,
    () => charset[Math.floor(Math.random() * charset.length)]
  );

/**
 * 为数字创建对应的 16 进制 hash
 * @param value
 */
const hashNumber = (value: number): string =>
  crypto
    .createHash("MD5")
    .update(value.toString())
    .digest("hex")
    .slice(-12)
    .split(/(?=(?:..)*$)/)
    .join(" ")
    .toUpperCase();

/**
 * 根据 base 字符串和 ID 位数创建对应的哈希字符数组
 * @param base
 * @param count
 */
const createRoutes = (base: string, count: number): Array<string> => {
  const array = [];
  for (let i = 0; i < count; i++)
    array.push(
      crypto
        .createHash("MD5")
        .update(`${base}${i.toString()}`)
        .digest("base64")
        .replace(/(\=|\+|\/)/g, "0")
        .substring(0, 22)
    );
  return array;
};

/**
 * @class Storage
 * 用于读取/写入服务器端的 data.json 文件
 */
class Storage {
  private _path: string = path.join(path.resolve(), "data.json");
  private _content: object = {};
  private _contentProxy: object;
  constructor() {
    if (!this.existsPersistent()) this.createPersistent();
    this.read();
  }
  public get content(): any {
    return this._contentProxy;
  }
  public set content(data: any) {
    this._content = data;
    const _this = this;
    const proxy = {
      get(target: any, key: any) {
        if (typeof target[key] === "object" && target[key] !== null)
          return new Proxy(target[key], proxy);
        else return target[key];
      },
      set(target: any, key: any, value: any): any {
        target[key] = value;
        _this.write(_this.content);
        return true;
      },
    };
    this._contentProxy = new Proxy(this._content, proxy);
    _this.write(_this.content);
  }
  private read(): Storage {
    return (
      (this.content = JSON.parse(
        fs.readFileSync(this._path).toString() || "{}"
      )),
      this
    );
  }
  private write(content: object): Storage {
    fs.writeFileSync(this._path, JSON.stringify(content, null, "\t"));
    return this;
  }
  private createPersistent() {
    this.write({});
  }
  private existsPersistent() {
    return fs.existsSync(this._path);
  }
}
const STORAGE: any = new Storage().content;
dotenv.config();

/****************************************************************************************************\
 * @global
 * 配置选项
 */
const WEBSERVER_DOMAIN_1: string =
  process.env["HOST_MAIN"] ?? "localhost:10080";
const WEBSERVER_DOMAIN_2: string =
  process.env["HOST_DEMO"] ?? "localhost:10081";
const WEBSERVER_PORT_1: number = +process.env["PORT_MAIN"] ?? 10080;
const WEBSERVER_PORT_2: number = +process.env["PORT_DEMO"] ?? 10081;
const CACHE_IDENTIFIER: string =
  STORAGE.cacheID ?? generateUUID("xxxxxxxx", "0123456789abcdef");

const N: number = 32; // 最多 2^N 数量的 ID
/*****************************************************************************************************/

const FILE =
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII=";
const webserver_1: express.Express = express();
const webserver_2: express.Express = express();
const maxN: number = 2 ** N - 1;

webserver_1.options("*", cors());
webserver_2.options("*", cors());

console.info(`forekie | 启动中 N=${N}, C-ID='${CACHE_IDENTIFIER}' ...`);
console.info(
  `forekie | There are ${Math.max(maxN - 1 - (STORAGE.index ?? 1), 0)}/${
    maxN - 1
  } unique identifiers left.`
);

/**
 * @class Webserver
 * Webserver defaults
 */
class Webserver {
  public static routes: Array<string> = createRoutes(CACHE_IDENTIFIER, N).map(
    (value: string) => `${CACHE_IDENTIFIER}:${value}`
  );

  public static getVector(identifier: number): Array<string> {
    const booleanVector: Array<boolean> = (identifier >>> 0)
      .toString(2)
      .padStart(this.routes.length, "0")
      .split("")
      .map((element: "0" | "1") => element === "1")
      .reverse();
    const vector = new Array<string>();
    booleanVector.forEach((value: boolean, index: number) =>
      value ? vector.push(this.getRouteByIndex(index)) : void 0
    );
    return vector;
  }

  public static getIdentifier(
    vector: Set<string>,
    size: number = vector.size
  ): number {
    return parseInt(
      this.routes
        .map((route: string) => (vector.has(route) ? 0 : 1))
        .join("")
        .substr(0, size)
        .split("")
        .reverse()
        .join(""),
      2
    );
  }
  public static hasRoute(route: string): boolean {
    return this.routes.includes(route);
  }
  public static getRouteByIndex(index: number): string {
    return this.routes[index] ?? null;
  }
  public static getIndexByRoute(route: string): number {
    return this.routes.indexOf(route) ?? null;
  }
  public static getNextRoute(route: string): string | null {
    const index = this.routes.indexOf(route);
    if (index === -1) throw "Route is not valid.";
    return this.getRouteByIndex(index + 1);
  }
  public static setCookie(
    res: express.Response,
    name: string,
    value: any,
    options: express.CookieOptions = {
      httpOnly: false,
      expires: new Date(Date.now() + 60 * 1000),
    }
  ): express.Response {
    return res.cookie(name, value, options), res;
  }
  public static sendFile(
    res: express.Response,
    route: string,
    options: any = {},
    type: string = "html"
  ): express.Response {
    let content = fs.readFileSync(route).toString();
    Object.keys(options)
      .sort((a: string, b: string) => b.length - a.length)
      .forEach((key: string) => {
        content = content.replace(
          new RegExp(`\{\{${key}\}\}`, "g"),
          (options[key]?.toString() || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;")
        );
      });
    res.header({
      "Cache-Control": "private, no-cache, no-store, must-revalidate",
      Expires: -1,
      Pragma: "no-cache",
    });
    res.type(type);
    return res.send(content), res;
  }
}

/**
 * @class Profile
 * Read / Write 用于存储正在写入 / 读取的用户图标缓存信息
 */
class Profile {
  public static list: Set<Profile> = new Set<Profile>();
  public static get(uid: string): Profile {
    return this.has(uid)
      ? Array.from(this.list)
          .filter((profile: Profile) => profile.uid === uid)
          ?.pop()
      : null;
  }
  public static has(uid: string): boolean {
    return Array.from(this.list).some(
      (profile: Profile) => profile.uid === uid
    );
  }
  public static from(uid: string, identifier?: number): Profile {
    return !this.has(uid) ? new Profile(uid, identifier) : null;
  }

  private _uid: string;
  private _vector: Array<string>;
  private _identifier: number = null;
  private _visitedRoutes: Set<string> = new Set<string>();
  private _storageSize: number = -1;

  constructor(uid: string, identifier: number = null) {
    this._uid = uid;
    if (identifier !== null)
      (this._identifier = identifier),
        (this._vector = Webserver.getVector(identifier));
    Profile.list.add(this);
  }
  public destructor() {
    Profile.list.delete(this);
  }
  public get uid(): string {
    return this._uid;
  }
  public get vector(): Array<string> {
    return this._vector;
  }
  public get visited(): Set<string> {
    return this._visitedRoutes;
  }
  public get identifier(): number {
    return this._identifier;
  }
  public getRouteByIndex(index: number): string {
    return this.vector[index] ?? null;
  }
  public _isReading(): boolean {
    return this._identifier === null;
  }
  public _visitRoute(route: string) {
    this._visitedRoutes.add(route);
  }
  public _calcIdentifier(): number {
    return (
      (this._identifier = Webserver.getIdentifier(
        this._visitedRoutes,
        this._storageSize
      )),
      this.identifier
    );
  }
  public _setStorageSize(size: number) {
    this._storageSize = size;
  }
  public get storageSize(): number {
    return this._storageSize;
  }
}

webserver_2.set("trust proxy", 1);
webserver_2.use(cookieParser());
webserver_2.use(
  (req: express.Request, res: express.Response, next: Function) => {
    if (new RegExp(`https?:\/\/${WEBSERVER_DOMAIN_2}`).test(req.headers.origin))
      res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
    res.header("Access-Control-Allow-Methods", "GET, OPTIONS");
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept"
    );
    return next();
  }
);

/**
 * @description
 * 防止对于 write URL 的恶意访问
 */
const midSet: Set<string> = new Set<string>();
const generateWriteToken = (): string => {
  const uuid = generateUUID();
  setTimeout(() => midSet.delete(uuid), 1_000 * 60);
  return midSet.add(uuid), uuid;
};
const deleteWriteToken = (token: string) => midSet.delete(token);
const hasWriteToken = (token: string): boolean => midSet.has(token);

/**
 * @description
 * 当有用户访问该 URL 时，则表示用户浏览器已经存在持久化的图标缓存，因此进入指纹读取模式
 * 该过程中，首先会生成一个 UUID 存储在浏览器中当作 cookie，然后在一系列页面跳转过程中当作临时的会话身份识别
 */
webserver_2.get("/read", (_req: express.Request, res: express.Response) => {
  const uid = generateUUID();
  console.info(`forekie | Visitor uid='${uid}' is known • Read`);
  const profile: Profile = Profile.from(uid);
  profile._setStorageSize(Math.floor(Math.log2(STORAGE.index ?? 1)) + 1);
  if (profile === null) return res.redirect("/read");
  Webserver.setCookie(res, "uid", uid);
  res.redirect(`/t/${Webserver.getRouteByIndex(0)}?f=${generateUUID()}`); // 使用随机的参数是为了防止浏览器使用页面缓存
});

/**
 * @description
 * 当用户访问 domain2/write URL 时，表示该用户初次访问，进入图标缓存写入模式
 */
webserver_2.get(
  "/write/:mid",
  (req: express.Request, res: express.Response) => {
    const mid = req.params.mid;
    if (!hasWriteToken(mid)) return res.redirect("/");
    res.clearCookie("mid");
    deleteWriteToken(mid);
    const uid = generateUUID();
    console.info(
      `forekie | Visitor uid='${uid}' is unknown • Write`,
      STORAGE.index
    );
    const profile: Profile = Profile.from(uid, STORAGE.index);
    if (profile === null) return res.redirect("/");
    STORAGE.index++;
    Webserver.setCookie(res, "uid", uid);
    res.redirect(`/t/${Webserver.getRouteByIndex(0)}`); // 在写入模式中，访问用户必然是第一次访问，因此不需要设置随机参数
  }
);

/**
 * @description
 * 对于 /t/* 的 URL，会将用户重定向至下一个路径直至结束
 */
webserver_2.get("/t/:ref", (req: express.Request, res: express.Response) => {
  const referrer: string = req.params.ref;
  const uid: string = req.cookies.uid;
  const profile: Profile = Profile.get(uid);

  if (!Webserver.hasRoute(referrer) || profile === null)
    return res.redirect("/");
  const route: string = Webserver.getNextRoute(referrer);

  /** 异常处理 */
  if (profile._isReading() && profile.visited.has(referrer))
    return res.redirect("/");

  let nextReferrer: string = null;
  const redirectCount: number = profile._isReading()
    ? profile.storageSize
    : Math.floor(Math.log2(profile.identifier)) + 1;

  if (route) nextReferrer = `t/${route}?f=${generateUUID()}`;
  if (!profile._isReading()) {
    if (Webserver.getIndexByRoute(referrer) >= redirectCount - 1)
      nextReferrer = "read"; // 异常处理
  } else if (
    Webserver.getIndexByRoute(referrer) >= redirectCount - 1 ||
    nextReferrer === null
  )
    nextReferrer = "identity";

  const bit = !profile._isReading() ? profile.vector.includes(referrer) : "{}";
  Webserver.sendFile(res, path.join(path.resolve(), "www/referrer.html"), {
    delay: profile._isReading() ? 500 : 800,
    referrer: nextReferrer,
    favicon: referrer,
    bit: bit,
    index: `${Webserver.getIndexByRoute(referrer) + 1} / ${redirectCount}`,
  });
});

/**
 * @description
 * 结束图标缓存读取之后，将用户定向至 domain2/idemtity，同时服务端根据遍历的图标请求情况返回计算所得的用户身份 ID
 */
webserver_2.get("/identity", (req: express.Request, res: express.Response) => {
  const uid: string = req.cookies.uid;
  const profile: Profile = Profile.get(uid);
  if (profile === null) return res.redirect("/");
  res.clearCookie("uid");
  res.clearCookie("vid");
  const identifier = profile._calcIdentifier();
  if (profile.visited.size === 0 || identifier === 0)
    return res.redirect(`/write/${generateWriteToken()}`);
  if (identifier !== maxN) {
    const identifierHash: string = hashNumber(identifier);
    console.info(
      `forekie | Visitor successfully identified as '${identifierHash}' • (#${identifier}).`
    );
    Webserver.sendFile(res, path.join(path.resolve(), "www/identity.html"), {
      hash: identifierHash,
      identifier: `#${identifier}`,

      url_workwise: `${WEBSERVER_DOMAIN_1}/workwise`,
      url_main: WEBSERVER_DOMAIN_1,
    });
  } else
    Webserver.sendFile(res, path.join(path.resolve(), "www/identity.html"), {
      hash: "** ** ** **",
      identifier: "该浏览器不受此追踪模型影响",

      url_workwise: `${WEBSERVER_DOMAIN_1}/workwise`,
      url_main: WEBSERVER_DOMAIN_1,
    });
});

/**
 * @description
 * 开始往浏览器中写入图标缓存
 */
webserver_2.get(
  `/${CACHE_IDENTIFIER}`,
  (req: express.Request, res: express.Response) => {
    const rid: boolean = !!req.cookies.rid;
    res.clearCookie("rid");
    if (!rid)
      Webserver.sendFile(res, path.join(path.resolve(), "www/redirect.html"), {
        url_demo: WEBSERVER_DOMAIN_2,
      });
    else
      Webserver.sendFile(res, path.join(path.resolve(), "www/launch.html"), {
        favicon: CACHE_IDENTIFIER,
      });
  }
);

/**
 * @description
 * demo 主页面会重定向至 domain2/{CACHE_IDENTIFIER} 处
 */
webserver_2.get("/", (_req: express.Request, res: express.Response) => {
  Webserver.setCookie(res, "rid", true);
  res.clearCookie("mid");
  res.redirect(`/${CACHE_IDENTIFIER}`);
});

/**
 * @description
 * 当用户访问该 URL 时，表示该用户为初次访问网站，因此返回对应的 favicon
 */
webserver_2.get("/l/:ref", (_req: express.Request, res: express.Response) => {
  console.info(`forekie | 检测到初次访问用户`);
  Webserver.setCookie(res, "mid", generateWriteToken());
  const data = Buffer.from(FILE, "base64");
  res.writeHead(200, {
    "Cache-Control": "public, max-age=31536000",
    Expires: new Date(Date.now() + 31536000000).toUTCString(),
    "Content-Type": "image/png",
    "Content-Length": data.length,
  });
  res.end(data);
});

webserver_2.get("/i/:ref", (req: express.Request, res: express.Response) => {
  const data = Buffer.from(FILE, "base64");
  res.writeHead(200, {
    "Cache-Control": "public, max-age=31536000",
    Expires: new Date(Date.now() + 31536000000).toUTCString(),
    "Content-Type": "image/png",
    "Content-Length": data.length,
  });
  res.end(data);
});

/**
 * @description
 * /f 处理不同模式下的图标请求
 * 写入模式下，根据用户的随机身份 ID，只有对应的部分 URL 下的 icon 会被响应
 * 读取模式下，所有请求均不进行响应
 */
webserver_2.get("/f/:ref", (req: express.Request, res: express.Response) => {
  const referrer: string = req.params.ref;
  const uid: string = req.cookies.uid;
  if (!Profile.has(uid) || !Webserver.hasRoute(referrer))
    return res.status(404), res.end();
  const profile: Profile = Profile.get(uid);
  if (profile._isReading()) {
    profile._visitRoute(referrer);
    console.info(
      `forekie | Favicon requested by uid='${uid}' • Read `,
      Webserver.getIndexByRoute(referrer),
      "•",
      Array.from(profile.visited).map((route) =>
        Webserver.getIndexByRoute(route)
      )
    );
    return; // res.type("gif"), res.status(404), res.end();
  }
  if (!profile.vector.includes(referrer)) {
    console.info(
      `forekie | Favicon requested by uid='${uid}' • Write`,
      Webserver.getIndexByRoute(referrer),
      "•",
      Array.from(profile.vector).map((route) =>
        Webserver.getIndexByRoute(route)
      )
    );
    return; // res.type("gif"), res.status(404), res.end();
  }
  const data = Buffer.from(FILE, "base64");
  res.writeHead(200, {
    "Cache-Control": "public, max-age=31536000",
    Expires: new Date(Date.now() + 31536000000).toUTCString(),
    "Content-Type": "image/png",
    "Content-Length": data.length,
  });
  res.end(data);
});

webserver_2.get(
  "/favicon.ico",
  (_req: express.Request, res: express.Response) => {
    res.sendFile(path.join(path.resolve(), "www/favicon.ico"));
  }
);

webserver_2.get("*", (req: express.Request, res: express.Response) => {
  Webserver.sendFile(res, path.join(path.resolve(), "www/404.html"), {
    path: decodeURIComponent(req.path),
    url_main: WEBSERVER_DOMAIN_1,
  });
});

webserver_2.listen(WEBSERVER_PORT_2, () =>
  console.info(
    `tracking model '${WEBSERVER_DOMAIN_2}' running on port:`,
    WEBSERVER_PORT_2
  )
);

webserver_1.use(
  "/assets",
  express.static(path.join(path.resolve(), "www/assets"), { index: false })
);
webserver_2.use(
  "/assets",
  express.static(path.join(path.resolve(), "www/assets"), { index: false })
);

webserver_1.get("/", (_req: express.Request, res: express.Response) => {
  Webserver.sendFile(res, path.join(path.resolve(), "www/index.html"), {
    url_demo: WEBSERVER_DOMAIN_2,
  });
});

// 正常发送首页的 favicon
webserver_1.get( 
  "/favicon.ico",
  (_req: express.Request, res: express.Response) => {
    res.sendFile(path.join(path.resolve(), "www/favicon.ico"));
  }
);

// 展示工作原理
webserver_1.get("/workwise", (_req: express.Request, res: express.Response) => {
  Webserver.sendFile(res, path.join(path.resolve(), "www/workwise.html"), {
    url_main: WEBSERVER_DOMAIN_1,
  });
});

// 方便浏览器端调试
webserver_1.get("/api", (_req: express.Request, res: express.Response) => {
  res.type("json");
  res.status(200);
  res.send({
    index: STORAGE.index,
    cache: STORAGE.cacheID,
    bits: Math.floor(Math.log2(STORAGE.index ?? 1)) + 1,
    N: N,
    maxN: maxN,
  });
});


// 对于其他任意未知请求，主域名跳转至主页，追踪模型域名跳转至 404 页面
webserver_1.get("*", (_req: express.Request, res: express.Response) => {
  res.redirect("/");
});


webserver_1.listen(WEBSERVER_PORT_1, () =>
  console.info(
    `homepage '${WEBSERVER_DOMAIN_1}' running on port:`,
    WEBSERVER_PORT_1
  )
);

STORAGE.index = STORAGE.index ?? 1;
STORAGE.cacheID = CACHE_IDENTIFIER;
