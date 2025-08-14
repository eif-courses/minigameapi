# 📦 CivilRegistry

A Go project built with REST API, server-side rendered frontend (Templ), PostgreSQL database, SQLC, Tailwind CSS, and modern developer tooling.

---

## 🚀 Stack & Tools

* **Go** – main backend language
* **PostgreSQL** – database [https://www.postgresql.org/download/](https://www.postgresql.org/download/)
* **Templ** – template engine: [https://templ.guide/](https://templ.guide/)
* **TemplUI** – UI component library: [https://templui.io/](https://templui.io/)
* **SQLC** – generate Go code from SQL queries: [https://sqlc.dev/](https://sqlc.dev/)
* **Tailwind CSS** – modern utility-first CSS
* **Zap** – structured logging: `go.uber.org/zap`
* **Goose** – database migrations: [https://github.com/pressly/goose](https://github.com/pressly/goose)
* **Air** – live reload for Go: [https://github.com/cosmtrek/air](https://github.com/cosmtrek/air)
* **Taskfile** – task runner: [https://taskfile.dev/](https://taskfile.dev/)

---

## ✅ Getting started

### 1️⃣ Install dependencies

```bash
# Go tools
go install github.com/pressly/goose/v3/cmd/goose@latest
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
go install github.com/cosmtrek/air@latest
go install github.com/a-h/templ/cmd/templ@latest

# Tailwind CSS
npm install -D tailwindcss
```

### 2️⃣ Migrations

Use Goose to manage database migrations:

```bash
goose up      # migrate up
goose reset   # reset database
```

### 3️⃣ SQLC generate Go code from queries

```bash
sqlc generate
```

Tutorials:

* [https://www.youtube.com/watch?v=VX6KzpjaPp8](https://www.youtube.com/watch?v=VX6KzpjaPp8)
* [https://www.youtube.com/watch?v=4E4d6anFz2Y\&t=1s](https://www.youtube.com/watch?v=4E4d6anFz2Y&t=1s)

### 4️⃣ Run project with Taskfile

Run watchers and development tools:

```bash
task dev
```

Tasks available:

* `task templ` – generate Templ files with watch
* `task server` – run backend with Air live reload
* `task tailwind` – build Tailwind CSS with watch
* `task up` – run migrations
* `task reset` – reset migrations
* `task gen` – run SQLC code generation

---

## 📦 Project structure

* REST API (handlers, services, models)
* MVC server-side templates with Templ

---

## 🧪 Tests

* Unit tests focused on handlers and service.go
* Need to add integration tests later

---

## 📝 Logger

Using Zap for structured logging:

```go
import "go.uber.org/zap"
```

---

## 🌱 Frontend

* Built with Templ and TemplUI for server-side rendered UI components.
* Tailwind CSS for styling.

---

## 📄 License

MIT
