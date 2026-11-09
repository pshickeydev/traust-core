"""The Django and DRF route matrix: include() chains and their prefixes, DRF routers and the
viewsets they register, each view's methods and guards, and what can't be placed."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files


def _write(root: Path, files: dict[str, str]) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)


def _rows(root: Path) -> dict[tuple[str, str], dict]:
    result = route_guards(tree_files(root)).model_dump(mode="json")
    return {(r["method"], r["pattern"]): r for r in result["routes"]}


def test_include_chains_join_their_prefixes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "site/settings.py": 'ROOT_URLCONF = "site.urls"\n',
            "site/urls.py": (
                "from django.urls import include, path, re_path\n"
                "urlpatterns = [\n"
                '    path("api/", include("notes.urls")),\n'
                '    re_path(r"^legacy/", include([re_path(r"^n/(?P<pk>\\d+)/$", views.note)])),\n'
                "]\n"
            ),
            "notes/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("notes/<int:pk>/", views.note)]\n'
            ),
            "notes/views.py": "def note(request, pk): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {("any", "api/notes/<int:pk>/"), ("any", "^legacy/n/(?P<pk>\\d+)/$")}
    assert rows[("any", "api/notes/<int:pk>/")]["handler"]["path"] == "notes/views.py"


def test_a_class_view_has_a_row_per_method_it_defines(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom .views import NoteView, NoteList\n"
                "urlpatterns = [\n"
                '    path("notes/<int:pk>/", NoteView.as_view()),\n'
                '    path("notes/", NoteList.as_view()),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.contrib.auth.mixins import LoginRequiredMixin\n"
                "from django.views import View\n"
                "from rest_framework.generics import ListCreateAPIView\n"
                "class NoteView(LoginRequiredMixin, View):\n"
                "    def get(self, request, pk): ...\n"
                "    def delete(self, request, pk): ...\n"
                "class NoteList(ListCreateAPIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "notes/<int:pk>/"),
        ("DELETE", "notes/<int:pk>/"),
        ("GET", "notes/"),
        ("POST", "notes/"),
    }
    assert rows[("DELETE", "notes/<int:pk>/")]["guards"] == ["LoginRequiredMixin"]
    assert rows[("DELETE", "notes/<int:pk>/")]["handler"]["line"] == 6
    assert rows[("POST", "notes/")]["guards"] == ["IsAuthenticated"]


def test_a_router_expands_to_list_detail_and_action_routes(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/settings.py": (
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': "
                "['rest_framework.permissions.IsAuthenticated']}\n"
            ),
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework.routers import DefaultRouter\n"
                "from .views import NoteViewSet\n"
                "router = DefaultRouter()\n"
                'router.register(r"notes", NoteViewSet)\n'
                'urlpatterns = [path("api/", include(router.urls))]\n'
            ),
            "app/views.py": (
                "from rest_framework import viewsets\n"
                "from rest_framework.decorators import action\n"
                "class NoteViewSet(viewsets.ReadOnlyModelViewSet):\n"
                '    lookup_field = "slug"\n'
                '    @action(detail=True, methods=["post"], permission_classes=[AllowAny])\n'
                "    def share(self, request, slug=None): ...\n"
                "    @action(detail=False)\n"
                "    def recent(self, request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "api/"),  # DefaultRouter's API root view
        ("GET", "api/notes/"),
        ("GET", "api/notes/<slug>/"),
        ("POST", "api/notes/<slug>/share/"),
        ("GET", "api/notes/recent/"),
    }
    # DRF's default permissions guard a viewset that names none
    assert rows[("GET", "api/notes/<slug>/")]["scope_guards"] == [
        "rest_framework.permissions.IsAuthenticated"
    ]
    # an action's own permission_classes replace the viewset's
    share = rows[("POST", "api/notes/<slug>/share/")]
    assert share["unguard_markers"] == ["AllowAny"] and share["scope_guards"] == []
    assert share["judgement_required"]


def test_drf_defaults_guard_only_drf_views(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/settings.py": (
                "REST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['IsAuthenticated']}\n"
            ),
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("page/", views.page), path("api/", views.api)]\n'
            ),
            "app/views.py": (
                "from rest_framework.decorators import api_view\n"
                "def page(request): ...\n"
                '@api_view(["GET"])\n'
                "def api(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "page/")]["scope_guards"] == []
    assert rows[("any", "page/")]["judgement_required"]
    assert rows[("GET", "api/")]["scope_guards"] == ["IsAuthenticated"]


def test_csrf_method_and_lookalike_decorators_are_not_guards(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("hook/", views.hook), path("me/", views.me)]\n'
            ),
            "app/views.py": (
                "from django.views.decorators.csrf import csrf_exempt\n"
                "from django.views.decorators.http import require_POST\n"
                "@csrf_exempt\n"
                "@require_POST\n"
                '@require_setting("SLACK_TOKEN")\n'
                "def hook(request): ...\n"
                "@login_required\n"
                "def me(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    # a name that only looks like a guard (`require_setting`) is none (D36)
    assert rows[("POST", "hook/")]["guards"] == [] and rows[("POST", "hook/")]["judgement_required"]
    assert rows[("any", "me/")]["guards"] == ["login_required"]


def test_what_the_walk_cant_place_is_listed_not_dropped(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "site/urls.py": (
                "from functools import reduce\nfrom operator import add\n"
                "from django.conf import settings\n"
                "from django.urls import include, path\n"
                "from django.contrib import admin\n"
                "from .utils import opt_slash_path\n"
                "from . import views\n"
                "prefix = settings.BASE\n"
                'core = [path("accounts/", include("allauth.urls")),\n'
                '        path("admin/", admin.site.urls)]\n'
                "groups = [core]\n"
                "if settings.DEBUG:\n"
                '    groups.append([opt_slash_path("_debug", views.debug)])\n'
                "urlpatterns = reduce(add, groups)\n"
                'urlpatterns += [path(f"{prefix}status/", views.status)]\n'
            ),
            "site/utils.py": (
                "from django.urls import re_path\n"
                "def opt_slash_path(route, view):\n"
                '    return re_path(rf"^{route}/?$", view)\n'
            ),
            "site/views.py": "def debug(request): ...\ndef status(request): ...\n",
            "site/plugins.py": (
                "from django.urls import path\n"
                "def plugin_urls():\n"
                '    return [path("plugin/", plugin_view)]\n'
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("any", "accounts/"),  # a library's urlconf
        ("any", "admin/"),
        ("any", "_debug"),  # through the checkout's own path() helper, conditionally added
        ("any", "[prefix]status/"),
        ("any", "plugin/"),  # built by a function: its mount is unknown
    }
    assert rows[("any", "[prefix]status/")]["pattern_dynamic"]
    assert rows[("any", "plugin/")]["pattern_dynamic"]
    assert not rows[("any", "_debug")]["pattern_dynamic"]
    assert rows[("any", "admin/")]["judgement_required"]


def test_a_decorator_applied_in_the_urlconf_guards_its_view(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.contrib.auth.decorators import login_required\n"
                "from django.views.decorators.cache import cache_page\n"
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [\n"
                '    path("a/<int:pk>/", login_required(views.Note.as_view())),\n'
                '    path("b/", cache_page(60)(login_required(views.page))),\n'
                '    path("c/", login_required(library.view)),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.views import View\n"
                "class Note(View):\n    def get(self, request, pk): ...\n"
                "def page(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/<int:pk>/")]["guards"] == ["login_required"]
    assert rows[("any", "b/")]["guards"] == ["login_required"]
    assert rows[("any", "c/")]["guards"] == ["login_required"]


def test_a_method_decorator_naming_one_method_guards_only_it(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom .views import Notes\n"
                'urlpatterns = [path("notes/<int:pk>/", Notes.as_view())]\n'
            ),
            "app/views.py": (
                "from django.contrib.auth.decorators import login_required\n"
                "from django.utils.decorators import method_decorator\n"
                "from rest_framework.views import APIView\n"
                '@method_decorator(login_required, name="post")\n'
                "class Notes(APIView):\n"
                "    authentication_classes = [SessionAuthentication]\n"
                "    def get(self, request, pk): ...\n"
                "    def post(self, request, pk): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("POST", "notes/<int:pk>/")]["guards"] == ["login_required"]
    # authentication_classes reads a caller but refuses no one
    assert rows[("GET", "notes/<int:pk>/")]["guards"] == []
    assert rows[("GET", "notes/<int:pk>/")]["judgement_required"]


def test_viewset_mappings_and_nested_routers(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import include, path\n"
                "from rest_framework_nested.routers import NestedSimpleRouter, SimpleRouter\n"
                "from .views import CommentViewSet, NoteViewSet\n"
                "router = SimpleRouter()\n"
                'router.register(r"notes", NoteViewSet)\n'
                'comments = NestedSimpleRouter(router, r"notes", lookup="note")\n'
                'comments.register(r"comments", CommentViewSet)\n'
                "urlpatterns = [\n"
                '    path("", include(router.urls)),\n'
                '    path("", include(comments.urls)),\n'
                '    path("mine/<int:pk>/", NoteViewSet.as_view({"get": "retrieve"})),\n'
                "]\n"
            ),
            "app/views.py": (
                "from rest_framework import mixins, viewsets\n"
                "class NoteViewSet(mixins.RetrieveModelMixin, viewsets.GenericViewSet):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "class CommentViewSet(viewsets.ViewSet):\n"
                "    def list(self, request, note_pk=None): ...\n"
                "    def destroy(self, request, note_pk=None, pk=None): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert set(rows) == {
        ("GET", "notes/<pk>/"),
        ("GET", "notes/<note_pk>/comments/"),
        ("DELETE", "notes/<note_pk>/comments/<pk>/"),
        ("GET", "mine/<int:pk>/"),
    }
    assert rows[("GET", "mine/<int:pk>/")]["guards"] == ["IsAuthenticated"]
    assert rows[("DELETE", "notes/<note_pk>/comments/<pk>/")]["guards"] == []


def test_permissions_are_read_per_method_and_in_method_resolution_order(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                "urlpatterns = [\n"
                '    path("a/", views.A.as_view()),\n'
                '    path("b/", views.B.as_view()),\n'
                '    path("c/", views.C.as_view()),\n'
                '    path("d/", views.D.as_view(permission_classes=[AllowAny])),\n'
                '    path("e/", views.E.as_view()),\n'
                "]\n"
            ),
            "app/views.py": (
                "from django.contrib.auth.mixins import LoginRequiredMixin\n"
                "from django.views import View\n"
                "from rest_framework.views import APIView\n"
                "class A(APIView):\n"
                "    permission_classes = [IsAuthenticatedOrReadOnly]\n"
                "    def get(self, request): ...\n"
                "    def post(self, request): ...\n"
                "class B(APIView):\n"
                "    permission_classes = [IsAuthenticated | ReadOnly]\n"
                "    def get(self, request): ...\n"
                "class C(View, LoginRequiredMixin):\n"  # View.dispatch runs first
                "    def get(self, request): ...\n"
                "class D(APIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    def get(self, request): ...\n"
                "class E(APIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    def get_permissions(self): ...\n"
                "    def get(self, request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/")]["unguard_markers"] == ["IsAuthenticatedOrReadOnly"]
    assert rows[("POST", "a/")]["guards"] == ["IsAuthenticatedOrReadOnly"]
    assert rows[("GET", "b/")]["judgement_required"]
    assert rows[("GET", "c/")]["guards"] == [] and rows[("GET", "c/")]["judgement_required"]
    assert rows[("GET", "d/")]["unguard_markers"] == ["AllowAny"]  # as_view initkwargs
    assert rows[("GET", "e/")]["unguard_markers"] == ["get_permissions"]


def test_drf_policy_decorators_count_only_below_api_view(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "app/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("a/", views.a), path("b/", views.b), path("c/", views.c)]\n'
            ),
            "app/views.py": (
                "from rest_framework.decorators import api_view, permission_classes\n"
                "@permission_classes([IsAuthenticated])\n"
                '@api_view(["GET"])\n'
                "def a(request): ...\n"
                '@api_view(["GET"])\n'
                "@permission_classes([IsAuthenticated])\n"
                "def b(request): ...\n"
                '@api_view(["POST"])\n'
                "@permission_classes([])\n"
                "@extend_schema(request=LoginSerializer)\n"
                "def c(request): ...\n"
            ),
        },
    )
    rows = _rows(tmp_path)
    assert rows[("GET", "a/")]["guards"] == [] and rows[("GET", "a/")]["judgement_required"]
    assert rows[("GET", "b/")]["guards"] == ["IsAuthenticated"]
    assert rows[("POST", "c/")]["guards"] == [] and rows[("POST", "c/")]["judgement_required"]


def test_settings_are_code_and_guard_only_their_own_project(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "accounts/settings.py": (
                'ROOT_URLCONF = "accounts.urls"\n'
                "MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
            ),
            "accounts/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("me/", views.me), path("health/", views.health)]\n'
            ),
            "accounts/views.py": (
                "from django.contrib.auth.decorators import login_not_required\n"
                "def me(request): ...\n"
                "@login_not_required\n"
                "def health(request): ...\n"
            ),
            "billing/settings.py": (
                'ROOT_URLCONF = "billing.urls"\n'
                "# MIDDLEWARE = ['django.contrib.auth.middleware.LoginRequiredMiddleware']\n"
                "MIDDLEWARE = []\n"
            ),
            "billing/urls.py": (
                "from django.urls import path\nfrom . import views\n"
                'urlpatterns = [path("invoices/", views.invoices)]\n'
            ),
            "billing/views.py": "def invoices(request): ...\n",
        },
    )
    rows = _rows(tmp_path)
    assert rows[("any", "me/")]["scope_guards"] == ["LoginRequiredMiddleware"]
    assert rows[("any", "health/")]["unguard_markers"] == ["login_not_required"]
    assert rows[("any", "invoices/")]["scope_guards"] == []


# Invented apps from independent blind reviews of the Django and Flask matrix: routes once
# missing, guards once shown that don't protect, prefixes once wrong; each with the rows it
# lists now (family, method, pattern, guards, judged, pattern computed).
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/django_flask_matrix_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize("case", _CASES, ids=[c["case"] for c in _CASES])
def test_matrix_holes_a_review_found_stay_closed(tmp_path: Path, case: dict) -> None:
    for rel, text in case["files"].items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dedent(text))
    rows = sorted(
        [
            r["family"],
            r["method"],
            r["pattern"],
            sorted({*r["guards"], *r["scope_guards"]}),
            r["judgement_required"],
            r["pattern_dynamic"],
        ]
        for r in route_guards(tree_files(tmp_path)).model_dump(mode="json")["routes"]
        if r["family"] in ("django-drf", "flask")
    )
    assert rows == case["rows"]
