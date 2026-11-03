"""Ownership of the object an Express id route acts on: each allowed shape beside code that looks
protected but isn't, which must stay judged."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

AUTH = """
import jwt from "jsonwebtoken";

export const requireAuth = (req, res, next) => {
  req.user = jwt.verify(req.headers.authorization, "k");
  next();
};
export const admin = (req, res, next) => (req.user.isAdmin ? next() : res.sendStatus(403));
export const auth = { required: requireAuth, optional: (req, res, next) => next() };
"""

MODELS = """
import mongoose from "mongoose";

const postSchema = new mongoose.Schema({ user: String, title: String, public: Boolean });
export const Post = mongoose.model("Post", postSchema);
"""

PRISMA = """
model Note {
  id      Int    @id
  ownerId Int
  title   String
}
"""

STORE = """
interface Holiday {
  id: string;
  name: string;
}
const comments = new Map<string, any>();
const holidays = new Map<string, Holiday>();

export const Comment = {
  get: (id: string) => comments.get(id),
  getFor: (author: string, id: string) => {
    const comment = comments.get(id);
    return comment?.author === author ? comment : undefined;
  },
  getAny: (author: string, id: string) => {
    const comment = comments.get(id);
    return comment?.author === author || comment ? comment : undefined;
  },
  remove: (id: string) => comments.delete(id),
};
export const Holidays = { get: (id: string) => holidays.get(id) };
"""

LOADERS = """
import { Post } from "./models";

export const loadOwnPost = async (req, res, next) => {
  req.post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!req.post) return res.sendStatus(404);
  next();
};
export const loadAnyPost = async (req, res, next) => {
  req.post = await Post.findById(req.params.id);
  next();
};
export const showPost = () => async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(404);
  res.json(post);
};
"""

CONTROLLER = """
const { Post } = require("./models");

exports.remove = async (req, res) => {
  await Post.deleteOne({ _id: req.params.id, user: req.user.id });
  res.sendStatus(204);
};
exports.show = async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
};
exports.mine = async (input, id) => {
  const me = input.user.id;
  return Post.findOne({ _id: id, user: me });
};
"""

ROUTES = """
import express from "express";
import { PrismaClient } from "@prisma/client";
import { requireAuth, admin, auth } from "./auth";
import { Post } from "./models";
import { Comment, Holidays } from "./store";
import { loadOwnPost, loadAnyPost, showPost } from "./loaders";
const posts = require("./controller");

const prisma = new PrismaClient();
const app = express();
const asyncHandler = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// shape 1: a query naming the caller, refused when absent
app.get("/scoped/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.status(404).json({});
  res.json(post);
});
app.delete("/scoped/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const post = await Post.findOne({ _id: id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  await Post.deleteOne({ _id: id });
  res.sendStatus(204);
});
app.delete("/orfail/:id", requireAuth, async (req, res) => {
  await Post.findOne({ _id: req.params.id, user: req.user.id }).orFail();
  await Post.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
app.get("/either/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({
    _id: req.params.id,
    $or: [{ user: req.user.id }, { public: true }],
  });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/body/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.body.user });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/fallback/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.query.user || req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.delete("/unrefused/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  await Post.deleteOne({ _id: req.params.id });
  res.json(post);
});
app.put("/update-filter/:id", requireAuth, async (req, res) => {
  await Post.updateOne({ _id: req.params.id }, { user: req.user.id });
  res.sendStatus(204);
});

// shape 2: a single read, then a refusal of a foreign record
app.delete("/checked/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({});
  if (post.user.toString() !== req.user.id) return res.status(403).json({});
  await Post.deleteOne({ _id: req.params.id });
  res.sendStatus(204);
});
app.delete("/combined/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) {
    res.status(403).json({});
    return;
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/thrown/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) throw new Error("forbidden");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/next/:id", requireAuth, async (req, res, next) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next(new Error("forbidden"));
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/superuser/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!req.user.isAdmin && post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/tried/:id", requireAuth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    if (post.user !== req.user.id) return res.sendStatus(403);
    await Post.deleteOne({ _id: req.params.id });
  } catch (err) {
    next(err);
  }
});
app.delete("/ok-send/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) {
    res.json({ ok: false });
    return;
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/no-return/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) {
    res.status(403).json({});
  }
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/redirect/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.redirect("/");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/next-route/:id", requireAuth, async (req, res, next) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return next("route");
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/public-flag/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.public !== true) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
  res.json(req.user);
});
app.delete("/record-flag/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post.isAdmin && post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/late/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  await Post.deleteOne({ _id: req.params.id });
  if (post.user !== req.user.id) return res.sendStatus(403);
});
app.delete("/caught/:id", requireAuth, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (post.user !== req.user.id) throw new Error("forbidden");
  } catch (err) {
    await Post.deleteOne({ _id: req.params.id });
  }
});
app.delete("/repointed/:id", requireAuth, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.sendStatus(403);
  req.params.id = req.body.id;
  await Post.deleteOne({ _id: req.params.id });
});
app.delete("/impersonated/:id", requireAuth, async (req, res) => {
  req.user = { id: req.body.owner };
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.sendStatus(403);
  await Post.deleteOne({ _id: req.params.id });
});

// shape 5: a store returning the record only when owned
app.get("/comments/:id", requireAuth, (req, res) => {
  const comment = Comment.getFor(req.user.sub, req.params.id);
  if (!comment) return res.sendStatus(404);
  res.json(comment);
});
app.get("/any-comments/:id", requireAuth, (req, res) => {
  const comment = Comment.getAny(req.user.sub, req.params.id);
  if (!comment) return res.sendStatus(404);
  res.json(comment);
});
app.delete("/comments/:id", requireAuth, (req, res) => {
  Comment.getFor(req.user.sub, req.params.id);
  Comment.remove(req.params.id);
  res.sendStatus(204);
});
app.get("/holidays/:id", requireAuth, (req, res) => res.json(Holidays.get(req.params.id)));

// Prisma
app.get("/notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), ownerId: req.user.id },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.get("/notes-or-throw/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findUniqueOrThrow({
    where: { id: Number(req.params.id), ownerId: req.user.id },
  });
  res.json(note);
});
app.get("/related-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), owner: { id: req.user.id } },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.get("/other-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.findFirst({
    where: { id: Number(req.params.id), owner: { id: { not: req.user.id } } },
  });
  if (!note) return res.sendStatus(404);
  res.json(note);
});
app.put("/claimed-notes/:id", requireAuth, async (req, res) => {
  const note = await prisma.note.update({
    where: { id: Number(req.params.id) },
    data: { ownerId: req.user.id },
  });
  res.json(note);
});

// who is calling, and what authenticates
app.get("/open/:id", async (req, res) => {
  res.json(await Post.findOne({ _id: req.params.id, user: req.user.id }));
});
app.get("/optional/:id", auth.optional, async (req, res) => {
  res.json(await Post.findById(req.params.id));
});
app.get("/admin/:id", requireAuth, admin, async (req, res) => {
  res.json(await Post.findById(req.params.id));
});
app.get("/locals/:id", requireAuth, async (req, res) => {
  const post = await Post.findOne({ _id: req.params.id, user: res.locals.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});

// handler forms and the route's chain
app.get("/factory/:id", requireAuth, showPost());
app.get("/wrapped/:id", requireAuth, asyncHandler(async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post || post.user !== req.user.id) return res.sendStatus(404);
  res.json(post);
}));
app.delete("/controller/:id", requireAuth, posts.remove);
app.delete("/loaded/:id", requireAuth, loadOwnPost, async (req, res) => {
  await req.post.remove();
  res.sendStatus(204);
});
app.delete("/loaded-any/:id", requireAuth, loadAnyPost, async (req, res) => {
  await req.post.remove();
  res.sendStatus(204);
});
app.get("/passed/:id", requireAuth, (req, res) => posts.show(req, res));
app.get("/handed-body/:id", requireAuth, async (req, res) => {
  const post = await posts.mine(req.body, req.params.id);
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.get("/destructured/:id", requireAuth, async ({ params, user }, res) => {
  res.json(await Post.findById(params.id));
});
app.get("/validated/:id", requireAuth, async (req, res) => {
  validationResult(req).throw();
  const post = await Post.findOne({ _id: req.params.id, user: req.user.id });
  if (!post) return res.sendStatus(404);
  res.json(post);
});
app.delete("/coded/:id", requireAuth, async (req, res) => {
  const code = 403;
  const post = await Post.findById(req.params.id);
  if (post.user !== req.user.id) return res.status(code).json({});
  await Post.deleteOne({ _id: req.params.id });
});
"""

PRELOADED = """
import express from "express";
import { requireAuth } from "./auth";
import { Post } from "./models";

const router = express.Router();
router.param("id", async (req, res, next, id) => {
  req.post = await Post.findById(id);
  next();
});
router.get("/:id", requireAuth, (req, res) => res.json(req.post));
const app = express();
app.use("/preloaded", router);
"""


def _tree(root: Path, files: dict[str, str]) -> dict:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    return route_guards(tree_files(root)).model_dump(mode="json")


def _row(result: dict, method: str, pattern: str) -> dict:
    [row] = [
        r
        for r in result["routes"]
        if r["family"] == "express" and r["method"] == method and r["pattern"] == pattern
    ]
    return row


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _tree(
        tmp_path_factory.mktemp("app"),
        {
            "src/auth.ts": AUTH,
            "src/models.ts": MODELS,
            "prisma/schema.prisma": PRISMA,
            "src/store.ts": STORE,
            "src/loaders.ts": LOADERS,
            "src/controller.js": CONTROLLER,
            "src/routes.ts": ROUTES,
            "src/preloaded.ts": PRELOADED,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/scoped/:id", "scoped"),  # shape 1, refused when absent
        ("DELETE", "/scoped/:id", "checked"),  # the id is verified for the delete
        ("DELETE", "/orfail/:id", "checked"),  # `.orFail()` refuses the absent record
        ("GET", "/either/:id", "unchecked"),  # `$or` doesn't narrow to the caller
        ("GET", "/body/:id", "caller-blind"),  # the request body as the owner
        ("GET", "/fallback/:id", "unchecked"),  # `req.query.user || req.user.id`
        ("DELETE", "/unrefused/:id", "unchecked"),  # nothing refused when absent
        ("PUT", "/update-filter/:id", "unchecked"),  # the owner in the update, not the filter
        ("DELETE", "/checked/:id", "checked"),  # shape 2
        ("DELETE", "/combined/:id", "checked"),  # `!post ||`, a send, then a bare return
        ("DELETE", "/thrown/:id", "checked"),  # a throw refuses
        ("DELETE", "/next/:id", "checked"),  # `return next(err)` refuses
        ("DELETE", "/superuser/:id", "checked"),  # the caller's admin flag bypasses (D10)
        ("DELETE", "/tried/:id", "checked"),  # inside the handler's closing `try`
        ("DELETE", "/ok-send/:id", "unchecked"),  # a 2xx answer isn't a refusal
        ("DELETE", "/no-return/:id", "unchecked"),  # the 403 falls through to the delete
        ("DELETE", "/redirect/:id", "unchecked"),  # a redirect isn't a 4xx refusal
        ("DELETE", "/next-route/:id", "unchecked"),  # `next("route")` runs the next route
        ("DELETE", "/public-flag/:id", "unchecked"),  # `public` is no owner
        ("DELETE", "/record-flag/:id", "unchecked"),  # the record's flag, not the caller's
        ("DELETE", "/late/:id", "unchecked"),  # deleted before the check
        ("DELETE", "/caught/:id", "unchecked"),  # `catch` runs when the check refuses
        ("DELETE", "/repointed/:id", "unchecked"),  # `req.params.id` rewritten after the check
        ("DELETE", "/impersonated/:id", "caller-blind"),  # `req.user` written by the handler
        ("GET", "/comments/:id", "checked"),  # shape 5, refused when absent
        ("GET", "/any-comments/:id", "unknown"),  # `||`: returned whenever present
        ("DELETE", "/comments/:id", "unknown"),  # the owned result is ignored
        ("GET", "/holidays/:id", "none"),  # a typed store of ownerless records
        ("GET", "/notes/:id", "scoped"),  # Prisma `where`
        ("GET", "/notes-or-throw/:id", "scoped"),  # `findUniqueOrThrow`
        ("GET", "/related-notes/:id", "scoped"),  # a relation filter `owner: { id: me }`
        ("GET", "/other-notes/:id", "unchecked"),  # `{ not: me }` is no equality
        ("PUT", "/claimed-notes/:id", "unchecked"),  # `data` isn't the filter
        ("GET", "/open/:id", "n/a"),  # no guard
        ("GET", "/optional/:id", "n/a"),  # an optional guard lets anyone in
        ("GET", "/admin/:id", "n/a"),  # an admin-only middleware
        ("GET", "/locals/:id", "scoped"),  # `res.locals.user` is the caller
        ("GET", "/factory/:id", "checked"),  # the handler a factory builds
        ("GET", "/wrapped/:id", "checked"),  # `asyncHandler(fn)`
        ("DELETE", "/controller/:id", "scoped"),  # `exports.remove` through `require`
        ("DELETE", "/loaded/:id", "scoped"),  # a loader middleware scoping the record
        ("DELETE", "/loaded-any/:id", "caller-blind"),  # a loader that loads anyone's
        ("GET", "/preloaded/:id", "unknown"),  # `router.param` loads it first
        ("GET", "/passed/:id", "scoped"),  # `posts.show(req, res)` continues the handler
        ("GET", "/handed-body/:id", "caller-blind"),  # a helper's `input.user` isn't the caller
        ("GET", "/destructured/:id", "unknown"),  # `({ params }, res)` isn't read
        ("GET", "/validated/:id", "scoped"),  # a library reading `req` loads nothing of ours
        ("DELETE", "/coded/:id", "unchecked"),  # a status we can't read isn't a refusal
    ],
)
def test_only_the_allowed_shapes_count_as_protection(
    app: dict, method: str, pattern: str, ownership: str
) -> None:
    row = _row(app, method, pattern)
    assert row["ownership"] == ownership
    if ownership in ("caller-blind", "unchecked"):
        assert row["judgement_required"]


def test_the_evidence_names_the_record_and_its_owner(app: dict) -> None:
    evidence = _row(app, "DELETE", "/public-flag/:id")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Post", "user")
    assert _row(app, "GET", "/other-notes/:id")["ownership_evidence"]["owner_field"] == "ownerId"


@pytest.mark.parametrize(
    ("middleware", "guarded"),
    [
        ("lusca.xssProtection(true)", False),  # security headers
        ("loginLimiter", False),  # a rate limiter
        ("requireAuth", True),
    ],
)
def test_what_authenticates_an_express_route(
    tmp_path: Path, middleware: str, guarded: bool
) -> None:
    code = (
        'import express from "express";\nconst app = express();\n'
        f"app.use({middleware});\n"
        'app.get("/things/:id", (req, res) => res.json(req.params.id));\n'
    )
    result = _tree(tmp_path, {"app.js": code})
    row = _row(result, "GET", "/things/:id")
    assert bool(row["guards"] or row["scope_guards"]) is guarded
