"""The Rails and Sinatra route x guard matrix: routes.rb resources and scopes, controller
before_action chains and skips, Sinatra filters, and the gaps for what isn't enumerated."""

from __future__ import annotations

from pathlib import Path

from traust_core.v1.providers import ruby_routes
from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

APP = (
    "class ApplicationController < ActionController::Base\n"
    "  before_action :authenticate_user!\n  before_action :set_locale\nend\n"
)


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _enum(root: Path) -> dict:
    return route_guards(tree_files(root)).model_dump(mode="json")


def _route(result: dict, method: str, pattern: str) -> dict:
    [row] = [r for r in result["routes"] if r["method"] == method and r["pattern"] == pattern]
    return row


def _patterns(result: dict, family: str) -> set[tuple[str, str]]:
    return {(r["method"], r["pattern"]) for r in result["routes"] if r["family"] == family}


def test_resources_map_to_actions_and_inherit_the_base_controller_guard(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  resources :posts, only: [:index, :show, :destroy]\nend\n",
    )
    _write(tmp_path, "app/controllers/application_controller.rb", APP)
    _write(
        tmp_path,
        "app/controllers/posts_controller.rb",
        "class PostsController < ApplicationController\n"
        "  skip_before_action :authenticate_user!, only: [:index]\n"
        "  def index; end\n  def show; end\n  def destroy\n    authorize @post\n  end\nend\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "rails") == {
        ("GET", "/posts"),
        ("GET", "/posts/:id"),
        ("DELETE", "/posts/:id"),
    }
    destroy = _route(result, "DELETE", "/posts/:id")
    assert destroy["guards"] == ["authenticate_user!", "call:authorize"]
    assert destroy["handler"]["path"] == "app/controllers/posts_controller.rb"
    index = _route(result, "GET", "/posts")
    assert index["guards"] == []
    assert index["unguard_markers"] == [f"{ruby_routes.SKIPPED}:authenticate_user!"]
    assert index["judgement_required"]
    assert result["coverage_gaps"] == []


def test_namespaces_nesting_members_and_explicit_verbs(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  root 'pages#home'\n"
        "  namespace :admin do\n"
        "    resources :users, except: [:new, :edit, :create, :update] do\n"
        "      member { post :ban }\n"
        "      resources :notes, only: :index\n    end\n  end\n"
        "  scope '/api' do\n    get '/health', to: 'status#show'\n"
        "    match '/hook', to: 'hooks#receive', via: [:get, :post]\n  end\n"
        "  resource :profile, only: [:show, :update]\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/admin/users_controller.rb",
        "module Admin\n  class UsersController < ApplicationController\n"
        "    before_action :require_admin!\n    def ban; end\n  end\nend\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "rails") >= {
        ("GET", "/"),
        ("GET", "/admin/users"),
        ("GET", "/admin/users/:id"),
        ("DELETE", "/admin/users/:id"),
        ("POST", "/admin/users/:id/ban"),
        ("GET", "/admin/users/:user_id/notes"),
        ("GET", "/api/health"),
        ("GET", "/api/hook"),
        ("POST", "/api/hook"),
        ("GET", "/profile"),
        ("PATCH", "/profile"),
        ("PUT", "/profile"),
    }
    ban = _route(result, "POST", "/admin/users/:id/ban")
    assert ban["handler"]["expr"] == "admin/users#ban" and ban["guards"] == ["require_admin!"]
    assert _route(result, "GET", "/profile")["handler"]["expr"] == "profiles#show"


def test_devise_authenticate_blocks_guard_their_routes_and_draw_includes(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  authenticate :admin do\n    mount Sidekiq::Web => '/sidekiq'\n  end\n"
        "  draw :api\nend\n",
    )
    _write(tmp_path, "config/routes/api.rb", "get '/api/ping', to: 'ping#show'\n")
    result = _enum(tmp_path)
    assert _route(result, "ALL", "/sidekiq")["scope_guards"] == ["devise:authenticate(admin)"]
    assert _route(result, "GET", "/api/ping")["registration"]["path"] == "config/routes/api.rb"


def test_only_and_except_on_callbacks(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :items, only: [:index, :create]\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/items_controller.rb",
        "class ItemsController < ActionController::API\n"
        "  before_action :verify_token, except: :index\n"
        "  http_basic_authenticate_with name: 'a', password: 'b', only: [:create]\nend\n",
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/items")["guards"] == []
    assert _route(result, "POST", "/items")["guards"] == [
        "verify_token",
        "http_basic_authenticate_with",
    ]


def test_sinatra_filters_rack_auth_and_body_guards(tmp_path):
    _write(
        tmp_path,
        "app.rb",
        "require 'sinatra'\n"
        "use Rack::Session::Cookie, secret: 'x'\n"
        "before '/admin/*' do\n  halt 401 unless authorized?\nend\n"
        "get '/' do\n  'hi'\nend\n"
        "get '/admin/stats' do\n  stats\nend\n"
        "post '/upload' do\n  protected!\n  save\nend\n"
        "namespace '/api' do\n  get '/ping' do\n    'pong'\n  end\nend\n",
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/")["scope_guards"] == []
    assert _route(result, "GET", "/admin/stats")["scope_guards"] == ["before:authorized?"]
    assert _route(result, "POST", "/upload")["guards"] == ["call:protected!"]
    assert ("GET", "/api/ping") in _patterns(result, "sinatra")


def test_a_sinatra_app_behind_rack_auth_is_guarded(tmp_path):
    _write(
        tmp_path,
        "app.rb",
        "class App < Sinatra::Base\n  use Rack::Auth::Basic do |u, p| check(u, p) end\n"
        "  get '/data' do\n    data\n  end\nend\n",
    )
    assert _route(_enum(tmp_path), "GET", "/data")["scope_guards"] == ["Rack::Auth::Basic"]


def test_without_the_ruby_grammar_routes_are_a_named_gap(tmp_path, monkeypatch):
    monkeypatch.setattr(ruby_routes, "parser", lambda: None)
    _write(tmp_path, "config/routes.rb", "Rails.application.routes.draw do\n  resources :a\nend\n")
    result = _enum(tmp_path)
    [gap] = result["coverage_gaps"]
    assert gap["system"] == "rails" and "tree-sitter-ruby" in gap["reason"]
    assert result["routes"] == []


def test_routes_with_no_recognized_shape_are_a_gap(tmp_path):
    _write(tmp_path, "config/routes.rb", "Rails.application.routes.draw do\nend\n")
    [gap] = _enum(tmp_path)["coverage_gaps"]
    assert gap["system"] == "rails" and "UNENUMERATED" in gap["reason"]


def test_actions_missing_a_callback_their_siblings_run_are_an_asymmetry(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :articles, only: [:index, :create]\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/articles_controller.rb",
        "class ArticlesController < ApplicationController\n"
        "  before_action :authenticate_user\n"
        "  before_action :authenticate_user!, except: [:index]\n"
        "  def index; end\n  def create; end\nend\n",
    )
    result = _enum(tmp_path)
    index = _route(result, "GET", "/articles")
    assert index["guards"] == ["authenticate_user"]
    assert index["asymmetry"] and index["judgement_required"]
    [asym] = [a for a in result["asymmetries"] if a["family"] == "rails"]
    assert asym["group"] == "ArticlesController" and asym["unguarded"] == ["GET /articles"]


def test_percent_literal_arrays_name_actions_and_callbacks(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :posts, only: %i[show destroy]\n"
        "  resources :tags, except: %w[index show new edit create update]\nend\n",
    )
    _write(tmp_path, "app/controllers/application_controller.rb", APP)
    _write(
        tmp_path,
        "app/controllers/posts_controller.rb",
        "class PostsController < ApplicationController\n"
        "  skip_before_action :authenticate_user!, only: %i[show]\nend\n",
    )
    result = _enum(tmp_path)
    assert _patterns(result, "rails") == {
        ("GET", "/posts/:id"),
        ("DELETE", "/posts/:id"),
        ("DELETE", "/tags/:id"),
    }
    assert _route(result, "GET", "/posts/:id")["guards"] == []
    assert _route(result, "DELETE", "/posts/:id")["guards"] == ["authenticate_user!"]


def test_a_resources_module_option_names_the_controller(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :posts, only: [:show], module: 'v2'\nend\n",
    )
    _write(tmp_path, "app/controllers/posts_controller.rb", "class PostsController; end\n")
    _write(
        tmp_path,
        "app/controllers/v2/posts_controller.rb",
        "module V2\n  class PostsController < ActionController::Base\n    def show; end\n"
        "  end\nend\n",
    )
    row = _route(_enum(tmp_path), "GET", "/posts/:id")
    assert row["handler"]["path"] == "app/controllers/v2/posts_controller.rb"


def test_a_superclass_resolves_where_ruby_looks_it_up(tmp_path):
    # `class A::B < Base` looks `Base` up at the top level, `module A; class B < Base` inside
    # `A` first; a superclass the checkout doesn't define is never another by its short name
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  get 'pub/:slug', to: 'pub/pages#show'\n  get 'api/:id', to: 'api/notes#show'\n"
        "  get 'shop/:id', to: 'shop/items#show'\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/base_controller.rb",
        "class BaseController < ActionController::Base\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/admin/base_controller.rb",
        "module Admin\n  class BaseController < ActionController::Base\n"
        "    before_action :authenticate_admin!\n  end\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/pub/pages/base_controller.rb",
        "class Pub::Pages::BaseController < BaseController\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/pub/pages_controller.rb",
        "class Pub::PagesController < Pub::Pages::BaseController\n  def show; end\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/api/notes_controller.rb",
        "class Api::NotesController < BaseController\n  def show; end\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/shop/items_controller.rb",
        "class Shop::ItemsController < Storefront::BaseController\n  def show; end\nend\n",
    )
    result = _enum(tmp_path)
    assert _route(result, "GET", "/pub/:slug")["guards"] == []
    assert _route(result, "GET", "/api/:id")["guards"] == []
    assert _route(result, "GET", "/shop/:id")["guards"] == []


def test_routes_nested_past_any_real_file_neither_crash_nor_hang(tmp_path):
    depth = 500
    routes = (
        "Rails.application.routes.draw do\n"
        + "".join("  " * k + 'scope "/x" do\n' for k in range(depth))
        + "  " * depth
        + "resources :notes, only: [:destroy]\n"
        + "".join("  " * k + "end\n" for k in reversed(range(depth)))
        + "  resources :tags, only: [:show]\nend\n"
    )
    _write(tmp_path, "config/routes.rb", routes)
    assert ("GET", "/tags/:id") in _patterns(_enum(tmp_path), "rails")


def test_a_guard_an_included_concern_declares_guards_the_route(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :notes, only: [:show]\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/concerns/authenticated.rb",
        "module Authenticated\n  extend ActiveSupport::Concern\n\n  included do\n"
        "    before_action :authenticate_user!\n  end\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/notes_controller.rb",
        "class NotesController < ActionController::Base\n  include Authenticated\n"
        "  def show; end\nend\n",
    )
    assert _route(_enum(tmp_path), "GET", "/notes/:id")["guards"] == ["authenticate_user!"]


def test_route_concerns_expand_every_name_their_on_option_and_only_in_their_app(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  concern :commentable do\n    resources :comments, only: [:index]\n  end\n"
        "  concern :previewable do\n    get :preview, on: :member\n"
        "    get :drafts, on: :collection\n  end\n"
        "  resources :posts, only: [:show] do\n    concerns :commentable, :previewable\n  end\n"
        "end\n",
    )
    _write(
        tmp_path,
        "spec/dummy/config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  resources :pages, only: [:show] do\n    concerns :commentable\n  end\nend\n",
    )
    patterns = _patterns(_enum(tmp_path), "rails")
    assert {
        ("GET", "/posts/:post_id/comments"),
        ("GET", "/posts/:id/preview"),
        ("GET", "/posts/drafts"),
    } <= patterns
    assert ("GET", "/pages/:page_id/comments") not in patterns  # the other app's concern


def test_only_an_engines_own_routes_take_its_isolated_namespace(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :invoices, only: [:show]\nend\n",
    )
    _write(
        tmp_path,
        "lib/billing/engine.rb",
        "module Billing\n  class Engine < ::Rails::Engine\n    isolate_namespace Billing\n"
        "  end\nend\n",
    )
    _write(
        tmp_path,
        "app/controllers/invoices_controller.rb",
        "class InvoicesController < ActionController::Base\n  def show; end\nend\n",
    )
    row = _route(_enum(tmp_path), "GET", "/invoices/:id")
    assert row["handler"]["path"] == "app/controllers/invoices_controller.rb"


def test_a_routes_file_drawn_under_two_scopes_gives_both_and_a_cycle_stops(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n"
        "  scope module: :admin, path: 'admin' do\n    draw :shared\n  end\n"
        "  scope module: :api, path: 'api' do\n    draw :shared\n  end\nend\n",
    )
    _write(
        tmp_path,
        "config/routes/shared.rb",
        "resources :notes, only: [:show]\ndraw :shared\n",
    )
    patterns = _patterns(_enum(tmp_path), "rails")
    assert {("GET", "/admin/notes/:id"), ("GET", "/api/notes/:id")} <= patterns


def test_a_singular_resources_collection_route_keeps_its_parent_id(tmp_path):
    _write(
        tmp_path,
        "config/routes.rb",
        "Rails.application.routes.draw do\n  resources :posts, only: [] do\n"
        "    resource :comment, only: [] do\n      get :preview, on: :collection\n"
        "    end\n  end\nend\n",
    )
    assert ("GET", "/posts/:post_id/comment/preview") in _patterns(_enum(tmp_path), "rails")
