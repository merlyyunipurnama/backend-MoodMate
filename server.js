const Hapi = require("@hapi/hapi");
const Bcrypt = require("bcryptjs");
const fetch = require("node-fetch");
const fs = require("fs").promises;
const path = require("path");

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const JOURNALS_FILE = path.join(DATA_DIR, "journals.json");

let users = [];
let sessions = new Map();
let journalEntries = [];
let idCounter = 1;

const generateId = () => `id_${Date.now()}_${idCounter++}`;
const getCurrentDate = () => new Date().toISOString();

const generateSessionId = () => {
  return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

const ensureDataDirectory = async () => {
  try {
    await fs.access(DATA_DIR);
  } catch {
    await fs.mkdir(DATA_DIR, { recursive: true });
    console.log("📁 Data directory created");
  }
};

const loadData = async () => {
  try {
    await ensureDataDirectory();

    try {
      const usersData = await fs.readFile(USERS_FILE, "utf8");
      users = JSON.parse(usersData);
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log("📄 Users file not found, starting with empty array");
        users = [];
        await saveUsers();
      } else {
        throw error;
      }
    }

    try {
      const journalsData = await fs.readFile(JOURNALS_FILE, "utf8");
      journalEntries = JSON.parse(journalsData);
    } catch (error) {
      if (error.code === "ENOENT") {
        console.log("📄 Journals file not found, starting with empty array");
        journalEntries = [];
        await saveJournals();
      } else {
        throw error;
      }
    }

    const allIds = [
      ...users.map((u) => u.id),
      ...journalEntries.map((j) => j.id),
    ];

    if (allIds.length > 0) {
      const maxId = Math.max(
        ...allIds.map((id) => {
          const match = id.match(/id_\d+_(\d+)/);
          return match ? parseInt(match[1]) : 0;
        })
      );
      idCounter = maxId + 1;
    }
  } catch (error) {
    console.error("❌ Error loading data:", error);
  }
};

const saveUsers = async () => {
  try {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (error) {
    console.error("❌ Error saving users:", error);
  }
};

const saveJournals = async () => {
  try {
    await fs.writeFile(JOURNALS_FILE, JSON.stringify(journalEntries, null, 2));
  } catch (error) {
    console.error("❌ Error saving journals:", error);
  }
};

const init = async () => {
  await loadData();

  const server = Hapi.server({
    port: 9000,
    host: "localhost",
    routes: {
      cors: {
        origin: ["*"],
        headers: ["Accept", "Content-Type", "If-None-Match", "X-Session-ID"],
        exposedHeaders: ["WWW-Authenticate", "Server-Authorization"],
        additionalExposedHeaders: ["Accept"],
        maxAge: 60,
        additionalHeaders: ["cache-control", "x-requested-with"],
      },
    },
  });

  const validateSession = (request) => {
    const sessionId = request.headers["x-session-id"];
    if (!sessionId || !sessions.has(sessionId)) {
      return null;
    }
    return sessions.get(sessionId);
  };

  server.route({
    method: "GET",
    path: "/api/health",
    handler: (request, h) => {
      return {
        status: "OK",
        message: "MoodMate Auth API is running",
        timestamp: getCurrentDate(),
        stats: {
          users: users.length,
          journals: journalEntries.length,
          sessions: sessions.size,
        },
      };
    },
  });

  server.route({
    method: "POST",
    path: "/api/auth/register",
    handler: async (request, h) => {
      const { name, email, password } = request.payload;

      if (users.find((u) => u.email === email)) {
        return h
          .response({
            success: false,
            message: "Email sudah terdaftar",
          })
          .code(400);
      }

      const hashedPassword = await Bcrypt.hash(password, 10);

      const user = {
        id: generateId(),
        name,
        email,
        password: hashedPassword,
        createdAt: getCurrentDate(),
      };

      users.push(user);
      await saveUsers();

      return {
        success: true,
        message: "User berhasil didaftarkan",
        data: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      };
    },
  });

  server.route({
    method: "POST",
    path: "/api/auth/login",
    handler: async (request, h) => {
      const { email, password } = request.payload;

      const user = users.find((u) => u.email === email);
      if (!user) {
        return h
          .response({
            success: false,
            message: "Email atau password salah",
          })
          .code(401);
      }

      const isValid = await Bcrypt.compare(password, user.password);
      if (!isValid) {
        return h
          .response({
            success: false,
            message: "Email atau password salah",
          })
          .code(401);
      }

      const sessionId = generateSessionId();
      sessions.set(sessionId, {
        userId: user.id,
        email: user.email,
        createdAt: getCurrentDate(),
      });

      return h
        .response({
          success: true,
          message: "Login berhasil",
          data: {
            sessionId: sessionId,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              createdAt: user.createdAt,
            },
          },
        })
        .header("X-Session-ID", sessionId);
    },
  });

  server.route({
    method: "GET",
    path: "/api/auth/profile",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        if (!user) {
          return h
            .response({
              success: false,
              message: "User tidak ditemukan",
            })
            .code(404);
        }

        return {
          success: true,
          message: "Profil berhasil diambil",
          data: {
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              createdAt: user.createdAt,
              updatedAt: user.updatedAt,
            },
          },
        };
      } catch (error) {
        console.error("Get profile error:", error);
        return h
          .response({
            success: false,
            message: "Gagal mengambil profil",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "PUT",
    path: "/api/auth/profile",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const userIndex = users.findIndex((u) => u.id === session.userId);
        if (userIndex === -1) {
          return h
            .response({
              success: false,
              message: "User tidak ditemukan",
            })
            .code(404);
        }

        const { name } = request.payload;

        if (!name || name.trim().length === 0) {
          return h
            .response({
              success: false,
              message: "Nama tidak boleh kosong",
            })
            .code(400);
        }

        if (name.trim().length < 2) {
          return h
            .response({
              success: false,
              message: "Nama minimal 2 karakter",
            })
            .code(400);
        }

        if (name.trim().length > 50) {
          return h
            .response({
              success: false,
              message: "Nama maksimal 50 karakter",
            })
            .code(400);
        }

        users[userIndex] = {
          ...users[userIndex],
          name: name.trim(),
          updatedAt: getCurrentDate(),
        };

        await saveUsers();

        const updatedUser = {
          id: users[userIndex].id,
          name: users[userIndex].name,
          email: users[userIndex].email,
          createdAt: users[userIndex].createdAt,
          updatedAt: users[userIndex].updatedAt,
        };

        return {
          success: true,
          message: "Profil berhasil diperbarui",
          data: {
            user: updatedUser,
          },
        };
      } catch (error) {
        console.error("Update profile error:", error);
        return h
          .response({
            success: false,
            message: "Gagal memperbarui profil",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "PUT",
    path: "/api/auth/change-password",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const userIndex = users.findIndex((u) => u.id === session.userId);
        if (userIndex === -1) {
          return h
            .response({
              success: false,
              message: "User tidak ditemukan",
            })
            .code(404);
        }

        const { currentPassword, newPassword } = request.payload;

        if (!currentPassword || currentPassword.trim().length === 0) {
          return h
            .response({
              success: false,
              message: "Password saat ini harus diisi",
            })
            .code(400);
        }

        if (!newPassword || newPassword.trim().length === 0) {
          return h
            .response({
              success: false,
              message: "Password baru harus diisi",
            })
            .code(400);
        }

        if (newPassword.length < 6) {
          return h
            .response({
              success: false,
              message: "Password baru minimal 6 karakter",
            })
            .code(400);
        }

        if (newPassword.length > 100) {
          return h
            .response({
              success: false,
              message: "Password baru maksimal 100 karakter",
            })
            .code(400);
        }

        const isCurrentPasswordValid = await Bcrypt.compare(
          currentPassword,
          users[userIndex].password
        );

        if (!isCurrentPasswordValid) {
          return h
            .response({
              success: false,
              message: "Password saat ini salah",
            })
            .code(400);
        }

        const isSamePassword = await Bcrypt.compare(
          newPassword,
          users[userIndex].password
        );

        if (isSamePassword) {
          return h
            .response({
              success: false,
              message: "Password baru tidak boleh sama dengan password lama",
            })
            .code(400);
        }

        const hashedNewPassword = await Bcrypt.hash(newPassword, 10);

        users[userIndex] = {
          ...users[userIndex],
          password: hashedNewPassword,
          updatedAt: getCurrentDate(),
        };

        await saveUsers();

        return {
          success: true,
          message: "Password berhasil diubah",
          data: {
            updatedAt: users[userIndex].updatedAt,
          },
        };
      } catch (error) {
        console.error("Change password error:", error);
        return h
          .response({
            success: false,
            message: "Gagal mengubah password",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "POST",
    path: "/api/journal",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        if (!user) {
          return h
            .response({
              success: false,
              message: "User tidak ditemukan",
            })
            .code(404);
        }

        const {
          catatan,
          mood,
          aktivitas = [],
          detailAktivitas = {},
        } = request.payload;

        if (!catatan || catatan.trim() === "") {
          return h
            .response({
              success: false,
              message: "Catatan tidak boleh kosong",
            })
            .code(400);
        }

        if (!mood || mood.trim() === "") {
          return h
            .response({
              success: false,
              message: "Mood tidak boleh kosong",
            })
            .code(400);
        }

        const journalEntry = {
          id: generateId(),
          userId: user.id,
          catatan,
          mood,
          aktivitas,
          detailAktivitas,
          createdAt: getCurrentDate(),
        };

        journalEntries.push(journalEntry);
        await saveJournals();

        return {
          success: true,
          message: "Journal entry berhasil dibuat",
          data: journalEntry,
        };
      } catch (error) {
        console.error("Create journal error:", error);
        return h
          .response({
            success: false,
            message: "Gagal membuat journal entry",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "GET",
    path: "/api/journal",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        if (!user) {
          return h
            .response({
              success: false,
              message: "User tidak ditemukan",
            })
            .code(404);
        }

        const userJournals = journalEntries
          .filter((entry) => entry.userId === user.id)
          .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        return {
          success: true,
          message: "Journal entries berhasil diambil",
          data: userJournals,
          total: userJournals.length,
        };
      } catch (error) {
        console.error("Get journals error:", error);
        return h
          .response({
            success: false,
            message: "Gagal mengambil journal entries",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "GET",
    path: "/api/journal/{id}",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        const { id } = request.params;

        const journalEntry = journalEntries.find(
          (entry) => entry.id === id && entry.userId === user.id
        );

        if (!journalEntry) {
          return h
            .response({
              success: false,
              message: "Journal entry tidak ditemukan",
            })
            .code(404);
        }

        return {
          success: true,
          data: journalEntry,
        };
      } catch (error) {
        console.error("Get journal by ID error:", error);
        return h
          .response({
            success: false,
            message: "Gagal mengambil journal entry",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "PUT",
    path: "/api/journal/{id}",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        const { id } = request.params;
        const { catatan, mood, aktivitas, detailAktivitas } = request.payload;

        const journalIndex = journalEntries.findIndex(
          (entry) => entry.id === id && entry.userId === user.id
        );

        if (journalIndex === -1) {
          return h
            .response({
              success: false,
              message: "Journal entry tidak ditemukan",
            })
            .code(404);
        }

        const updatedEntry = {
          ...journalEntries[journalIndex],
          ...(catatan && { catatan }),
          ...(mood && { mood }),
          ...(aktivitas && { aktivitas }),
          ...(detailAktivitas && { detailAktivitas }),
          updatedAt: getCurrentDate(),
        };

        journalEntries[journalIndex] = updatedEntry;
        await saveJournals();

        return {
          success: true,
          message: "Journal entry berhasil diupdate",
          data: updatedEntry,
        };
      } catch (error) {
        console.error("Update journal error:", error);
        return h
          .response({
            success: false,
            message: "Gagal mengupdate journal entry",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "DELETE",
    path: "/api/journal/{id}",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        const user = users.find((u) => u.id === session.userId);
        const { id } = request.params;

        const journalIndex = journalEntries.findIndex(
          (entry) => entry.id === id && entry.userId === user.id
        );

        if (journalIndex === -1) {
          return h
            .response({
              success: false,
              message: "Journal entry tidak ditemukan",
            })
            .code(404);
        }

        const deletedEntry = journalEntries.splice(journalIndex, 1)[0];
        await saveJournals();

        return {
          success: true,
          message: "Journal entry berhasil dihapus",
          data: deletedEntry,
        };
      } catch (error) {
        console.error("Delete journal error:", error);
        return h
          .response({
            success: false,
            message: "Gagal menghapus journal entry",
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "POST",
    path: "/api/predict-mood",
    handler: async (request, h) => {
      try {
        const session = validateSession(request);
        if (!session) {
          return h
            .response({
              success: false,
              message: "Session tidak valid",
            })
            .code(401);
        }

        console.log("Received prediction request:", request.payload);

        const mlResponse = await fetch("http://127.0.0.1:8000/predict", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: request.payload.text }),
        });

        console.log("ML Service response status:", mlResponse.status);

        if (!mlResponse.ok) {
          const error = await mlResponse.json();
          console.log("ML Service error:", error);
          throw new Error(error.detail);
        }

        const result = await mlResponse.json();
        console.log("ML Service result:", result);

        return result;
      } catch (error) {
        console.error("Prediction error:", error);
        return h
          .response({
            success: false,
            message: "Prediction failed: " + error.message,
          })
          .code(500);
      }
    },
  });

  server.route({
    method: "POST",
    path: "/api/auth/logout",
    handler: async (request, h) => {
      const sessionId = request.headers["x-session-id"];

      if (sessionId && sessions.has(sessionId)) {
        sessions.delete(sessionId);
      }

      return {
        success: true,
        message: "Logout berhasil",
      };
    },
  });

  const gracefulShutdown = async () => {
    console.log("\nGraceful shutdown initiated...");
    try {
      await saveUsers();
      await saveJournals();
      console.log("All data saved successfully");
      await server.stop();
      console.log("Server stopped");
      process.exit(0);
    } catch (error) {
      console.error("Error during shutdown:", error);
      process.exit(1);
    }
  };

  process.on("SIGTERM", gracefulShutdown);
  process.on("SIGINT", gracefulShutdown);

  await server.start();
  console.log("Server running on %s", server.info.uri);
  console.log("   - Health Check: GET /api/health");
  console.log("   - Register: POST /api/auth/register");
  console.log("   - Login: POST /api/auth/login");
  console.log("   - Profile: GET /api/auth/profile");
  console.log("   - Update Profile: PUT /api/auth/profile");
  console.log("   - Change Password: PUT /api/auth/change-password");
  console.log("   - Logout: POST /api/auth/logout");
  console.log("   - Predict Mood: POST /api/predict-mood");
  console.log("   - Create Journal: POST /api/journal");
  console.log("   - Get Journals: GET /api/journal");
  console.log("   - Get Journal by ID: GET /api/journal/{id}");
  console.log("   - Update Journal: PUT /api/journal/{id}");
  console.log("   - Delete Journal: DELETE /api/journal/{id}");
};

process.on("unhandledRejection", (err) => {
  console.log(err);
  process.exit(1);
});

init();
