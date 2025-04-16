var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import "dotenv/config";
import express3 from "express";

// server/routes.ts
import { createServer } from "http";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  areas: () => areas,
  areasRelations: () => areasRelations,
  insertAreaSchema: () => insertAreaSchema,
  insertListingSchema: () => insertListingSchema,
  insertUserSchema: () => insertUserSchema,
  listings: () => listings,
  listingsRelations: () => listingsRelations,
  users: () => users,
  usersRelations: () => usersRelations
});
import { pgTable, text, serial, integer, timestamp, doublePrecision } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { relations } from "drizzle-orm";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull()
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true
});
var areas = pgTable("areas", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  // Turkish name
  name_en: text("name_en").notNull()
  // English name
});
var insertAreaSchema = createInsertSchema(areas).pick({
  name: true,
  name_en: true
});
var listings = pgTable("listings", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  price: doublePrecision("price").notNull(),
  imageUrl: text("image_url"),
  userId: integer("user_id").notNull().references(() => users.id),
  areaId: integer("area_id").notNull().references(() => areas.id),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertListingSchema = createInsertSchema(listings).pick({
  title: true,
  description: true,
  price: true,
  imageUrl: true,
  areaId: true,
  userId: true
});
var usersRelations = relations(users, ({ many }) => ({
  listings: many(listings)
}));
var areasRelations = relations(areas, ({ many }) => ({
  listings: many(listings)
}));
var listingsRelations = relations(listings, ({ one }) => ({
  user: one(users, {
    fields: [listings.userId],
    references: [users.id]
  }),
  area: one(areas, {
    fields: [listings.areaId],
    references: [areas.id]
  })
}));

// server/db.ts
import "dotenv/config";
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
if (process.env.DATABASE_URL?.includes("neon.tech")) {
  neonConfig.webSocketConstructor = ws;
}
if (!process.env.DATABASE_URL) {
  console.error("ERROR: No DATABASE_URL found. Database connection required.");
  console.error("Please set DATABASE_URL in your .env file.");
  process.exit(1);
}
var pool;
var db;
try {
  if (process.env.DATABASE_URL?.startsWith("postgresql://")) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      // Maximum number of clients in the pool
      idleTimeoutMillis: 3e4,
      // How long a client is allowed to remain idle before being closed
      connectionTimeoutMillis: 5e3
      // How long to wait for a connection to become available
    });
  } else {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
  }
  db = drizzle({ client: pool, schema: schema_exports });
  console.log("Connected to PostgreSQL database");
  pool.query("SELECT NOW()", (err, res) => {
    if (err) {
      console.warn("Warning: Initial connection test query failed:", err.message);
    } else {
      console.log("Database connection verified successfully at:", res.rows[0].now);
    }
  });
} catch (error) {
  console.error("FATAL ERROR: Failed to connect to PostgreSQL database:", error);
  console.error("Please check your database connection settings and make sure PostgreSQL is running.");
  console.error("Make sure: 1) PostgreSQL service is running 2) Credentials are correct 3) Database exists");
  process.exit(1);
}

// server/storage.ts
import { eq, desc, sql, or } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
var DatabaseStorage = class {
  sessionStore;
  constructor() {
    const PostgresSessionStore = connectPg(session);
    this.sessionStore = new PostgresSessionStore({
      pool,
      createTableIfMissing: true
    });
  }
  // User methods
  async getUser(id) {
    try {
      const result = await db.select().from(users).where(eq(users.id, id)).limit(1);
      return result.length > 0 ? result[0] : void 0;
    } catch (error) {
      console.error("Database error in getUser:", error);
      throw error;
    }
  }
  async getUserByUsername(username) {
    try {
      const result = await db.select().from(users).where(eq(users.username, username)).limit(1);
      return result.length > 0 ? result[0] : void 0;
    } catch (error) {
      console.error("Database error in getUserByUsername:", error);
      throw error;
    }
  }
  async createUser(insertUser) {
    try {
      const result = await db.insert(users).values(insertUser).returning();
      return result[0];
    } catch (error) {
      console.error("Database error in createUser:", error);
      throw error;
    }
  }
  // Area methods
  async getAreas() {
    try {
      return await db.select().from(areas);
    } catch (error) {
      console.error("Database error in getAreas:", error);
      throw error;
    }
  }
  async getArea(id) {
    try {
      const result = await db.select().from(areas).where(eq(areas.id, id)).limit(1);
      return result.length > 0 ? result[0] : void 0;
    } catch (error) {
      console.error("Database error in getArea:", error);
      throw error;
    }
  }
  async createArea(insertArea) {
    try {
      const result = await db.insert(areas).values(insertArea).returning();
      return result[0];
    } catch (error) {
      console.error("Database error in createArea:", error);
      throw error;
    }
  }
  // Listing methods
  async getListings(options) {
    try {
      let areaFilter = void 0;
      if (options.area && options.area !== "all" && options.area !== "") {
        const areaId = parseInt(options.area, 10);
        if (!isNaN(areaId)) {
          areaFilter = areaId;
          console.log(`Filtering listings by area ID: ${areaId}`);
        } else {
          console.log(`Invalid area ID format: ${options.area}`);
        }
      } else {
        console.log('No area filter applied or "all" selected');
      }
      if (options.locationEnabled && areaFilter) {
        console.log(`LOCATION ENABLED: Strictly filtering to show ONLY listings from area ID ${areaFilter}`);
      }
      const strictLocationFiltering = options.locationEnabled && areaFilter !== void 0;
      if (strictLocationFiltering) {
        console.log(`** STRICT LOCATION FILTERING ACTIVE: Only showing listings from area ID ${areaFilter} **`);
      }
      let query;
      if (areaFilter !== void 0) {
        console.log(`STRICTLY filtering listings to only show area ID: ${areaFilter}`);
        query = db.select().from(listings).where(eq(listings.areaId, areaFilter));
      } else {
        query = db.select().from(listings);
      }
      let countQuery;
      if (areaFilter !== void 0) {
        countQuery = db.select({ count: sql`count(*)::int` }).from(listings).where(eq(listings.areaId, areaFilter));
      } else {
        countQuery = db.select({ count: sql`count(*)::int` }).from(listings);
      }
      const totalResult = await countQuery;
      const total = Number(totalResult[0]?.count || 0);
      const listingsResult = await query.orderBy(desc(listings.createdAt)).limit(options.limit).offset(options.offset);
      console.log(`Found ${listingsResult.length} listings for${areaFilter ? ` area ${areaFilter}` : " all areas"} out of ${total} total`);
      return {
        listings: listingsResult,
        total
      };
    } catch (error) {
      console.error("Database error in getListings:", error);
      throw error;
    }
  }
  async getListing(id) {
    try {
      const result = await db.select().from(listings).where(eq(listings.id, id)).limit(1);
      return result.length > 0 ? result[0] : void 0;
    } catch (error) {
      console.error("Database error in getListing:", error);
      throw error;
    }
  }
  async createListing(insertListing) {
    try {
      const result = await db.insert(listings).values(insertListing).returning();
      return result[0];
    } catch (error) {
      console.error("Database error in createListing:", error);
      throw error;
    }
  }
  async deleteListingById(id) {
    try {
      const result = await db.delete(listings).where(eq(listings.id, id)).returning({ id: listings.id });
      return result.length > 0;
    } catch (error) {
      console.error("Database error in deleteListingById:", error);
      throw error;
    }
  }
  async cleanupOldListings() {
    try {
      const oneWeekAgo = /* @__PURE__ */ new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      try {
        await db.update(listings).set({ imageUrl: null }).where(
          or(
            sql`${listings.imageUrl} LIKE '%placeholder.com%'`,
            sql`${listings.imageUrl} IS NOT NULL AND ${listings.imageUrl} NOT LIKE '/uploads/%' AND ${listings.imageUrl} NOT LIKE 'http%'`
          )
        );
        console.log("Updated any problematic image URLs to null");
      } catch (fixError) {
        console.error("Error fixing problematic image URLs:", fixError);
      }
      const result = await db.delete(listings).where(sql`${listings.createdAt} < ${oneWeekAgo.toISOString()}`).returning({ id: listings.id });
      const deletedCount = result.length;
      console.log(`Cleaned up ${deletedCount} listings older than one week`);
      return deletedCount;
    } catch (error) {
      console.error("Database error in cleanupOldListings:", error);
      throw error;
    }
  }
};
var storage = new DatabaseStorage();

// server/routes.ts
import { z } from "zod";

// server/upload.ts
import multer from "multer";
import path from "path";
import fs from "fs";
var uploadDir = path.join(process.cwd(), "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  try {
    fs.mkdirSync(uploadDir, { recursive: true });
    console.log(`Created uploads directory at: ${uploadDir}`);
  } catch (error) {
    console.error(`Failed to create uploads directory at ${uploadDir}:`, error);
    console.log("IMPORTANT: You may need to manually create the directory:");
    console.log("mkdir -p public/uploads");
    console.log("OR on Windows:");
    console.log("mkdir public\\uploads");
  }
}
try {
  const testFilePath = path.join(uploadDir, "test-write-permission.txt");
  fs.writeFileSync(testFilePath, "Testing write permissions");
  fs.unlinkSync(testFilePath);
  console.log("Upload directory is writable!");
} catch (error) {
  console.warn("WARNING: Upload directory may not be writable:", error);
  console.log("You may need to set permissions on this folder:");
  console.log('On Windows: icacls "public\\uploads" /grant:r Everyone:(OI)(CI)F');
}
var storage2 = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function(req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const extension = path.extname(file.originalname);
    cb(null, "image-" + uniqueSuffix + extension);
  }
});
var fileFilter = (req, file, cb) => {
  if (!file.originalname.match(/\.(jpg|jpeg|png|gif|webp)$/i)) {
    return cb(new Error("Only image files are allowed!"));
  }
  cb(null, true);
};
var upload = multer({
  storage: storage2,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024
    // 5MB max file size
  }
});
function getFileUrl(filename) {
  return `/uploads/${filename}`;
}

// server/routes.ts
import path2 from "path";
import fs2 from "fs";
import express from "express";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  if (!stored.includes(".")) {
    console.log("Legacy password format detected, using direct comparison");
    return supplied === stored;
  }
  try {
    const [hashed, salt] = stored.split(".");
    if (!salt) {
      console.error("Invalid password format: missing salt");
      return false;
    }
    const hashedBuf = Buffer.from(hashed, "hex");
    const suppliedBuf = await scryptAsync(supplied, salt, 64);
    return timingSafeEqual(hashedBuf, suppliedBuf);
  } catch (error) {
    console.error("Error comparing passwords:", error);
    return false;
  }
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET || "kolaybul-secret-key",
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: false,
      // set to true in production with HTTPS
      maxAge: 1e3 * 60 * 60 * 24 * 7
      // 1 week
    }
  };
  app2.set("trust proxy", 1);
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !await comparePasswords(password, user.password)) {
          return done(null, false);
        } else {
          return done(null, user);
        }
      } catch (error) {
        return done(error);
      }
    })
  );
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).json({ message: "Username already exists" });
      }
      const hashedPassword = await hashPassword(req.body.password);
      const user = await storage.createUser({
        ...req.body,
        password: hashedPassword
      });
      req.login(user, (err) => {
        if (err) return next(err);
        return res.status(201).json(user);
      });
    } catch (error) {
      next(error);
    }
  });
  app2.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err, user) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ message: "Invalid credentials" });
      req.login(user, (loginErr) => {
        if (loginErr) return next(loginErr);
        return res.status(200).json(user);
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ message: "Not authenticated" });
    res.json(req.user);
  });
}

// server/routes.ts
function validateImageUrl(url) {
  if (!url) return false;
  if (url.startsWith("/uploads/")) {
    return true;
  }
  try {
    new URL(url);
  } catch {
    return false;
  }
  const imageExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg"];
  return imageExtensions.some((ext) => url.toLowerCase().endsWith(ext)) || // url.includes('placeholder.com') || // Removed placeholder images
  url.includes("unsplash.com") || // Unsplash images
  url.includes("cloudinary.com");
}
async function registerRoutes(app2) {
  const uploadsPath = path2.join(process.cwd(), "public/uploads");
  if (!fs2.existsSync(uploadsPath)) {
    fs2.mkdirSync(uploadsPath, { recursive: true });
  }
  app2.use("/uploads", express.static(uploadsPath));
  setupAuth(app2);
  const requireAuth = (req, res, next) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    next();
  };
  app2.get("/api/auth/me", (req, res) => {
    res.redirect(307, "/api/user");
  });
  app2.get("/api/areas", async (_req, res) => {
    try {
      const areas2 = await storage.getAreas();
      res.json(areas2);
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.get("/api/listings", async (req, res) => {
    try {
      const page = parseInt(req.query.page || "1", 10);
      const limit = parseInt(req.query.limit || "33", 10);
      const offset = (page - 1) * limit;
      const area = req.query.area;
      const locationEnabledRaw = req.query.locationEnabled;
      const locationEnabled = locationEnabledRaw === "true";
      console.log(`Location Detection Status: Raw value="${locationEnabledRaw}", Parsed=${locationEnabled}`);
      console.log(`GET /api/listings with area=${area}, locationEnabled=${locationEnabled}, page=${page}, limit=${limit}`);
      if (locationEnabled) {
        if (!area || area === "all" || area === "") {
          console.log("Location detection enabled but no valid area provided - sending empty response");
          return res.json({
            listings: [],
            totalPages: 0,
            currentPage: page,
            totalListings: 0
          });
        }
        console.log(`Location detection enabled, strictly filtering by area ID: ${area}`);
      }
      const { listings: listings2, total } = await storage.getListings({
        area,
        limit,
        offset,
        locationEnabled
        // Pass location enabled status to the storage layer
      });
      console.log(`Retrieved ${listings2.length} listings out of ${total} total for area=${area || "all"}, locationEnabled=${locationEnabled}`);
      const listingsWithAreaInfo = await Promise.all(
        listings2.map(async (listing) => {
          const area2 = await storage.getArea(listing.areaId);
          return {
            ...listing,
            area: area2?.name || "Unknown",
            area_en: area2?.name_en || "Unknown"
          };
        })
      );
      res.json({
        listings: listingsWithAreaInfo,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        totalListings: total
      });
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.get("/api/listings/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const listing = await storage.getListing(id);
      if (!listing) {
        return res.status(404).json({ message: "Listing not found" });
      }
      const area = await storage.getArea(listing.areaId);
      const listingWithArea = {
        ...listing,
        area: area?.name || "Unknown",
        area_en: area?.name_en || "Unknown"
      };
      res.json(listingWithArea);
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.post("/api/listings", requireAuth, async (req, res) => {
    try {
      const listingInput = z.object({
        title: z.string().min(5),
        description: z.string().min(10),
        price: z.number().positive(),
        area: z.string(),
        // This is the area ID
        imageUrl: z.string().optional()
      });
      const validationResult = listingInput.safeParse(req.body);
      if (!validationResult.success) {
        return res.status(400).json({ message: "Invalid input", errors: validationResult.error.format() });
      }
      const { title, description, price, area, imageUrl } = validationResult.data;
      const userId = req.user?.id;
      const areaId = parseInt(area, 10);
      const areaExists = await storage.getArea(areaId);
      if (!areaExists) {
        return res.status(400).json({ message: "Invalid area" });
      }
      let processedImageUrl = imageUrl;
      if (!processedImageUrl) {
        processedImageUrl = void 0;
      } else if (!processedImageUrl.startsWith("/uploads/") && !validateImageUrl(processedImageUrl)) {
        processedImageUrl = void 0;
      }
      if (!userId) {
        return res.status(401).json({ message: "Not authenticated" });
      }
      const newListing = await storage.createListing({
        title,
        description,
        price,
        imageUrl: processedImageUrl,
        userId,
        areaId
      });
      res.status(201).json({
        ...newListing,
        area: areaExists.name,
        area_en: areaExists.name_en
      });
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.delete("/api/listings/:id", requireAuth, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const userId = req.user?.id;
      const listing = await storage.getListing(id);
      if (!listing) {
        return res.status(404).json({ message: "Listing not found" });
      }
      if (listing.userId !== userId) {
        return res.status(403).json({ message: "Forbidden: Not your listing" });
      }
      await storage.deleteListingById(id);
      res.json({ message: "Listing deleted successfully" });
    } catch (error) {
      res.status(500).json({ message: "Internal server error" });
    }
  });
  app2.post("/api/upload", requireAuth, upload.single("image"), (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }
      const imageUrl = getFileUrl(req.file.filename);
      res.json({
        imageUrl,
        message: "File uploaded successfully"
      });
    } catch (error) {
      res.status(500).json({ message: "Error uploading file" });
    }
  });
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express2 from "express";
import fs3 from "fs";
import path4 from "path";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path3 from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path3.resolve(import.meta.dirname, "client", "src"),
      "@shared": path3.resolve(import.meta.dirname, "shared"),
      "@assets": path3.resolve(import.meta.dirname, "attached_assets")
    }
  },
  root: path3.resolve(import.meta.dirname, "client"),
  build: {
    outDir: path3.resolve(import.meta.dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path4.resolve(
        import.meta.dirname,
        "..",
        "client",
        "index.html"
      );
      let template = await fs3.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path4.resolve(import.meta.dirname, "public");
  if (!fs3.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path4.resolve(distPath, "index.html"));
  });
}

// server/seed.ts
import { sql as sql2 } from "drizzle-orm";
async function seedAreas() {
  const defaultAreas = [
    { name: "Adalar", name_en: "Adalar" },
    { name: "Arnavutk\xF6y", name_en: "Arnavutkoy" },
    { name: "Ata\u015Fehir", name_en: "Atasehir" },
    { name: "Avc\u0131lar", name_en: "Avcilar" },
    { name: "Ba\u011Fc\u0131lar", name_en: "Bagcilar" },
    { name: "Bah\xE7elievler", name_en: "Bahcelievler" },
    { name: "Bak\u0131rk\xF6y", name_en: "Bakirkoy" },
    { name: "Ba\u015Fak\u015Fehir", name_en: "Basaksehir" },
    { name: "Bayrampa\u015Fa", name_en: "Bayrampasa" },
    { name: "Be\u015Fikta\u015F", name_en: "Besiktas" },
    { name: "Beykoz", name_en: "Beykoz" },
    { name: "Beylikd\xFCz\xFC", name_en: "Beylikduzu" },
    { name: "Beyo\u011Flu", name_en: "Beyoglu" },
    { name: "B\xFCy\xFCk\xE7ekmece", name_en: "Buyukcekmece" },
    { name: "\xC7atalca", name_en: "Catalca" },
    { name: "\xC7ekmek\xF6y", name_en: "Cekmekoy" },
    { name: "Esenler", name_en: "Esenler" },
    { name: "Esenyurt", name_en: "Esenyurt" },
    { name: "Ey\xFCpsultan", name_en: "Eyupsultan" },
    { name: "Fatih", name_en: "Fatih" },
    { name: "Gaziosmanpa\u015Fa", name_en: "Gaziosmanpasa" },
    { name: "G\xFCng\xF6ren", name_en: "Gungoren" },
    { name: "Kad\u0131k\xF6y", name_en: "Kadikoy" },
    { name: "K\xE2\u011F\u0131thane", name_en: "Kagithane" },
    { name: "Kartal", name_en: "Kartal" },
    { name: "K\xFC\xE7\xFCk\xE7ekmece", name_en: "Kucukcekmece" },
    { name: "Maltepe", name_en: "Maltepe" },
    { name: "Pendik", name_en: "Pendik" },
    { name: "Sancaktepe", name_en: "Sancaktepe" },
    { name: "Sar\u0131yer", name_en: "Sariyer" },
    { name: "Silivri", name_en: "Silivri" },
    { name: "Sultanbeyli", name_en: "Sultanbeyli" },
    { name: "Sultangazi", name_en: "Sultangazi" },
    { name: "\u015Eile", name_en: "Sile" },
    { name: "\u015Ei\u015Fli", name_en: "Sisli" },
    { name: "Tuzla", name_en: "Tuzla" },
    { name: "\xDCmraniye", name_en: "Umraniye" },
    { name: "\xDCsk\xFCdar", name_en: "Uskudar" },
    { name: "Zeytinburnu", name_en: "Zeytinburnu" }
  ];
  try {
    try {
      const countResult = await db.select({ count: sql2`count(*)::int` }).from(areas);
      const count = Number(countResult[0]?.count || 0);
      if (count > 0) {
        console.log(`[seed] ${count} areas already exist, skipping seed`);
        return;
      }
      await db.insert(areas).values(defaultAreas);
      console.log("[seed] Areas seeded successfully");
    } catch (innerError) {
      if (String(innerError).includes('relation "areas" does not exist')) {
        console.log("[seed] Areas table does not exist yet, it will be created when needed");
      } else {
        throw innerError;
      }
    }
  } catch (error) {
    if (error && typeof error === "object" && "type" in error && error.type === "error") {
      console.log("[seed] WebSocket connection issue - areas may need to be seeded manually");
    } else {
      console.error("[seed] Error seeding areas:", error);
    }
    console.log("[seed] Will continue without seeding. You may need to create areas manually.");
  }
}

// server/index.ts
if (!process.env.SESSION_SECRET) {
  process.env.SESSION_SECRET = "local-development-secret-key";
}
var app = express3();
app.use(express3.json());
app.use(express3.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path5 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path5.startsWith("/api")) {
      let logLine = `${req.method} ${path5} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  try {
    await seedAreas();
  } catch (error) {
    console.error("Failed to seed database:", error);
  }
  const server = await registerRoutes(app);
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";
    res.status(status).json({ message });
    throw err;
  });
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 5e3;
  const isWindows = process.platform === "win32";
  const runCleanupJob = async () => {
    try {
      console.log("Running scheduled cleanup of old listings...");
      const deletedCount = await storage.cleanupOldListings();
      console.log(`Cleanup complete: deleted ${deletedCount} listings older than one week`);
    } catch (error) {
      console.error("Error during scheduled cleanup:", error);
    }
    setTimeout(runCleanupJob, 24 * 60 * 60 * 1e3);
  };
  runCleanupJob().catch((err) => console.error("Failed to run initial cleanup job:", err));
  if (isWindows) {
    server.listen(port, "localhost", () => {
      log(`serving on localhost:${port}`);
    });
  } else {
    server.listen({
      port,
      host: "0.0.0.0",
      reusePort: true
    }, () => {
      log(`serving on port ${port}`);
    });
  }
})();
