"""Ownership of the object a Rails id route acts on: each allowed shape beside code that looks
protected but isn't, which must stay judged."""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from traust_core.v1.providers.route_guards import route_guards
from traust_core.v1.providers.tree import tree_files

ROUTES = """
Rails.application.routes.draw do
  resources :notes, only: [:show, :update, :destroy]
  resources :projects, only: [:show] do
    resources :tasks, only: [:show, :destroy]
  end
  scope "/s" do
    get "scoped/:id", to: "shapes#scoped"
    get "find_by/:id", to: "shapes#find_by_refused"
    get "find_by_unrefused/:id", to: "shapes#find_by_unrefused"
    get "where/:id", to: "shapes#where_caller"
    get "find_by_bang/:id", to: "shapes#find_by_bang"
    get "param_owner/:id", to: "shapes#param_owner"
    get "string_where/:id", to: "shapes#string_where"
    get "widened/:id", to: "shapes#widened"
    get "unscoped/:id", to: "shapes#unscoped"
    delete "checked/:id", to: "shapes#checked"
    delete "returned/:id", to: "shapes#returned"
    delete "raised/:id", to: "shapes#raised"
    delete "rendered/:id", to: "shapes#rendered"
    delete "admin_bypass/:id", to: "shapes#admin_bypass"
    delete "redirected/:id", to: "shapes#redirected"
    delete "no_return/:id", to: "shapes#no_return"
    delete "leaks/:id", to: "shapes#leaks"
    delete "late/:id", to: "shapes#late"
    delete "param_compare/:id", to: "shapes#param_compare"
    delete "id_vs_record/:id", to: "shapes#id_vs_record"
    get "ignored/:id", to: "shapes#ignored"
    get "opaque/:id", to: "shapes#opaque"
    get "helper/:id", to: "shapes#helper"
  end
  scope "/c" do
    delete "owned/:id", to: "callbacks#owned"
    delete "redirect_cb/:id", to: "callbacks#redirect_cb"
    delete "unowned/:id", to: "callbacks#unowned"
  end
  scope "/p" do
    delete "policy/:id", to: "policies#destroy"
    patch "lenient/:id", to: "policies#update"
    get "admin_policy/:id", to: "policies#show"
    delete "unread/:id", to: "policies#unread"
    get "scope/:id", to: "policies#scoped"
    get "open_scope/:id", to: "policies#open_scope"
  end
  resources :chores, only: [:update, :destroy]
  resources :errands, only: [:destroy], controller: "cancan_errands"
  scope "/who" do
    get "open/:id", to: "open#show"
    get "forged/:id", to: "forged#show"
    get "session_ivar/:id", to: "session_ivar#show"
    get "param_ivar/:id", to: "param_ivar#show"
    get "own_current_user/:id", to: "own_current_user#show"
  end
  namespace :admin do
    resources :notes, only: [:destroy]
    resources :reports, only: [:destroy]
  end
end
"""

SCHEMA = """
ActiveRecord::Schema[7.1].define(version: 1) do
  create_table "users" do |t|
    t.string "email"
    t.boolean "admin"
  end
  create_table "notes" do |t|
    t.references "user"
    t.text "body"
    t.boolean "public"
  end
  create_table "projects" do |t|
    t.references "user"
    t.string "name"
  end
  create_table "tasks" do |t|
    t.references "user"
    t.references "project"
    t.string "title"
  end
  create_table "chores" do |t|
    t.references "user"
    t.string "title"
  end
  create_table "holidays" do |t|
    t.string "name"
  end
end
"""

MODELS = {
    "app/models/application_record.rb": "class ApplicationRecord < ActiveRecord::Base\nend\n",
    "app/models/user.rb": (
        "class User < ApplicationRecord\n  has_many :notes\n  has_many :projects\nend\n"
    ),
    "app/models/note.rb": "class Note < ApplicationRecord\n  belongs_to :user\nend\n",
    "app/models/project.rb": (
        "class Project < ApplicationRecord\n  belongs_to :user\n  has_many :tasks\nend\n"
    ),
    "app/models/task.rb": (
        "class Task < ApplicationRecord\n  belongs_to :user\n  belongs_to :project\nend\n"
    ),
    "app/models/holiday.rb": "class Holiday < ApplicationRecord\nend\n",
    "app/models/chore.rb": "class Chore < ApplicationRecord\n  belongs_to :user\nend\n",
}

APPLICATION = """
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  before_action :authenticate_user!
end
"""

SHAPES = """
class ShapesController < ApplicationController
  def scoped
    @note = current_user.notes.find(params[:id])
  end

  def find_by_refused
    note = current_user.notes.find_by(id: params[:id])
    head :not_found and return unless note
    Note.find(params[:id]).touch
  end

  def find_by_unrefused
    note = current_user.notes.find_by(id: params[:id])
    Note.find(params[:id]).touch
  end

  def where_caller
    @note = Note.where(user: current_user).find(params[:id])
  end

  def find_by_bang
    @note = Note.find_by!(id: params[:id], user_id: current_user.id)
  end

  def param_owner
    @note = Note.where(user_id: params[:user_id]).find(params[:id])
  end

  def string_where
    @note = Note.where("user_id = ?", params[:owner]).find(params[:id])
  end

  def widened
    @note = current_user.notes.or(Note.where(public: true)).find(params[:id])
  end

  def unscoped
    @note = current_user.notes.unscoped.find(params[:id])
  end

  def checked
    note = Note.find(params[:id])
    head :forbidden and return unless note.user == current_user
    note.destroy
  end

  def returned
    note = Note.find(params[:id])
    return head(:forbidden) if note.user_id != current_user.id
    note.destroy
  end

  def raised
    note = Note.find(params[:id])
    raise ActiveRecord::RecordNotFound unless note.user == current_user
    note.destroy
  end

  def rendered
    note = Note.find(params[:id])
    if note.user != current_user
      render json: { error: "forbidden" }, status: :forbidden
      return
    end
    note.destroy
  end

  def admin_bypass
    note = Note.find(params[:id])
    head :forbidden and return unless current_user.admin? || note.user == current_user
    note.destroy
  end

  def redirected
    note = Note.find(params[:id])
    redirect_to root_path and return unless note.user == current_user
    note.destroy
  end

  def no_return
    note = Note.find(params[:id])
    head :forbidden unless note.user == current_user
    note.destroy
  end

  def leaks
    note = Note.find(params[:id])
    render json: note, status: :forbidden and return unless note.user == current_user
    note.destroy
  end

  def late
    note = Note.find(params[:id])
    note.destroy
    head :forbidden and return unless note.user == current_user
  end

  def param_compare
    note = Note.find(params[:id])
    head :forbidden and return unless note.user_id == params[:owner_id]
    note.destroy
  end

  def id_vs_record
    note = Note.find(params[:id])
    head :forbidden and return unless note.user_id == current_user
    note.destroy
  end

  def ignored
    render plain: "hello"
  end

  def opaque
    NoteExporter.new(params.permit!).run
  end

  def helper
    note.touch
  end

  private

  def note
    @note ||= current_user.notes.find(params[:id])
  end
end
"""

CALLBACKS = """
class CallbacksController < ApplicationController
  before_action :set_note
  before_action :require_owner, only: [:owned]
  before_action :redirect_stranger, only: [:redirect_cb]

  def owned
    @note.destroy
  end

  def redirect_cb
    @note.destroy
  end

  def unowned
    @note.destroy
  end

  private

  def set_note
    @note = Note.find(params[:id])
  end

  def require_owner
    head :forbidden unless @note.user == current_user
  end

  def redirect_stranger
    redirect_to notes_path, alert: "Not yours" unless @note.user == current_user
  end
end
"""

NOTES = """
class NotesController < ApplicationController
  def show
    @note = current_user.notes.find(params[:id])
  end

  def update
    note = Note.find(params[:id])
    note.update(body: params[:body])
  end

  def destroy
    Note.find(params[:id]).destroy
  end
end
"""

TASKS = """
class TasksController < ApplicationController
  before_action :set_project

  def show
    @task = @project.tasks.find(params[:id])
  end

  def destroy
    Project.find(params[:project_id]).tasks.find(params[:id]).destroy
  end

  private

  def set_project
    @project = current_user.projects.find(params[:project_id])
  end
end
"""

POLICIES = """
class PoliciesController < ApplicationController
  def destroy
    note = Note.find(params[:id])
    authorize note
    note.destroy
  end

  def update
    note = Note.find(params[:id])
    authorize note
    note.update(body: params[:body])
  end

  def show
    @note = Note.find(params[:id])
    authorize @note
  end

  def unread
    task = Task.find(params[:id])
    authorize task
    task.destroy
  end

  def scoped
    @note = policy_scope(Note).find(params[:id])
  end

  def open_scope
    @project = policy_scope(Project).find(params[:id])
  end
end
"""

NOTE_POLICY = """
class NotePolicy < ApplicationPolicy
  def destroy?
    record.user == user
  end

  def update?
    true
  end

  def show?
    user.admin? || record.user_id == user.id
  end

  class Scope < Scope
    def resolve
      scope.where(user: user)
    end
  end
end
"""

PROJECT_POLICY = """
class ProjectPolicy < ApplicationPolicy
  class Scope < Scope
    def resolve
      scope.all
    end
  end
end
"""

CANCAN = """
class ChoresController < ApplicationController
  load_and_authorize_resource

  def update
    @chore.update(title: params[:title])
  end

  def destroy
    @chore.destroy
  end
end
"""

ABILITY = """
class Ability
  include CanCan::Ability

  def initialize(user)
    can :destroy, Chore, user_id: user.id
    can :update, Chore
    can :manage, :all if user.admin?
  end
end
"""

WHO = {
    "app/controllers/open_controller.rb": """
class OpenController < ActionController::Base
  def show
    @note = Note.find(params[:id])
  end
end
""",
    "app/controllers/forged_controller.rb": """
class ForgedController < ApplicationController
  before_action :act_as

  def show
    @note = current_user.notes.find(params[:id])
  end

  private

  def act_as
    @current_user = User.find(params[:as]) if params[:as]
  end
end
""",
    "app/controllers/session_ivar_controller.rb": """
class SessionIvarController < ActionController::Base
  before_action :authenticate

  def show
    @note = @viewer.notes.find(params[:id])
  end

  private

  def authenticate
    @viewer = User.find_by(id: session[:user_id])
    head :unauthorized unless @viewer
  end
end
""",
    "app/controllers/own_current_user_controller.rb": """
class OwnCurrentUserController < ApplicationController
  def show
    @note = current_user.notes.find(params[:id])
  end

  private

  def current_user
    @current_user ||= User.find(params[:as] || session[:uid])
  end
end
""",
    "app/controllers/param_ivar_controller.rb": """
class ParamIvarController < ActionController::Base
  before_action :authenticate

  def show
    @note = @viewer.notes.find(params[:id])
  end

  private

  def authenticate
    @viewer = User.find_by(id: params[:viewer_id])
    head :unauthorized unless @viewer
  end
end
""",
}

ADMIN = {
    "app/controllers/admin/base_controller.rb": """
module Admin
  class BaseController < ApplicationController
    before_action :require_admin

    private

    def require_admin
      head :forbidden unless current_user.admin?
    end
  end
end
""",
    "app/controllers/admin/notes_controller.rb": """
module Admin
  class NotesController < BaseController
    def destroy
      Note.find(params[:id]).destroy
    end
  end
end
""",
    "app/controllers/admin/reports_controller.rb": """
module Admin
  class ReportsController < ApplicationController
    before_action :require_admin

    def destroy
      Note.find(params[:id]).destroy
    end

    private

    def require_admin
      Rails.logger.info("admin area")
    end
  end
end
""",
}


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
        if r["family"] == "rails" and r["method"] == method and r["pattern"] == pattern
    ]
    return row


@pytest.fixture(scope="module")
def app(tmp_path_factory: pytest.TempPathFactory) -> dict:
    return _tree(
        tmp_path_factory.mktemp("rails"),
        {
            "config/routes.rb": ROUTES,
            "db/schema.rb": SCHEMA,
            **MODELS,
            "app/controllers/application_controller.rb": APPLICATION,
            "app/controllers/shapes_controller.rb": SHAPES,
            "app/controllers/callbacks_controller.rb": CALLBACKS,
            "app/controllers/notes_controller.rb": NOTES,
            "app/controllers/tasks_controller.rb": TASKS,
            "app/controllers/policies_controller.rb": POLICIES,
            "app/controllers/chores_controller.rb": CANCAN,
            "app/controllers/cancan_errands_controller.rb": (
                "class CancanErrandsController < ApplicationController\n"
                "  load_and_authorize_resource\n\n  def destroy\n    @errand.destroy\n  end\nend\n"
            ),
            **WHO,
            **ADMIN,
            "app/policies/application_policy.rb": (
                "class ApplicationPolicy\n  attr_reader :user, :record\nend\n"
            ),
            "app/policies/note_policy.rb": NOTE_POLICY,
            "app/policies/project_policy.rb": PROJECT_POLICY,
            "app/models/ability.rb": ABILITY,
        },
    )


@pytest.mark.parametrize(
    ("method", "pattern", "ownership"),
    [
        ("GET", "/s/scoped/:id", "scoped"),  # shape 1: a caller association
        ("GET", "/s/find_by/:id", "checked"),  # `find_by` refused when nil verifies the id
        ("GET", "/s/find_by_unrefused/:id", "unchecked"),  # nil not refused
        ("GET", "/s/where/:id", "scoped"),  # `where(user: current_user)`
        ("GET", "/s/find_by_bang/:id", "scoped"),  # `find_by!(…, user_id: current_user.id)`
        ("GET", "/s/param_owner/:id", "caller-blind"),  # the owner from params
        ("GET", "/s/string_where/:id", "caller-blind"),  # a string condition
        ("GET", "/s/widened/:id", "unchecked"),  # `.or(…)` widens the association
        ("GET", "/s/unscoped/:id", "unchecked"),  # `unscoped` drops it
        ("DELETE", "/s/checked/:id", "checked"),  # shape 2: `head :forbidden and return unless`
        ("DELETE", "/s/returned/:id", "checked"),  # `return head(:forbidden) if`
        ("DELETE", "/s/raised/:id", "checked"),  # `raise … unless`
        ("DELETE", "/s/rendered/:id", "checked"),  # `if …; render status: :forbidden; return; end`
        ("DELETE", "/s/admin_bypass/:id", "checked"),  # the caller's admin flag (D10)
        ("DELETE", "/s/redirected/:id", "unchecked"),  # a redirect in the action (D16)
        ("DELETE", "/s/no_return/:id", "unchecked"),  # the response falls through
        ("DELETE", "/s/leaks/:id", "unchecked"),  # a 403 sending the record
        ("DELETE", "/s/late/:id", "unchecked"),  # destroyed before the check
        ("DELETE", "/s/param_compare/:id", "caller-blind"),  # compared with params
        ("DELETE", "/s/id_vs_record/:id", "unchecked"),  # an id against a record is never equal
        ("GET", "/s/ignored/:id", "unknown"),  # the id read nowhere we can see
        ("GET", "/s/opaque/:id", "unknown"),  # `params.permit!` handed to a service
        ("GET", "/s/helper/:id", "scoped"),  # a memoized helper
        ("DELETE", "/c/owned/:id", "checked"),  # a callback loads, another refuses
        ("DELETE", "/c/redirect_cb/:id", "checked"),  # a callback's redirect halts the action
        ("DELETE", "/c/unowned/:id", "caller-blind"),  # loaded by a callback, never checked
        ("GET", "/notes/:id", "scoped"),
        ("PATCH", "/notes/:id", "caller-blind"),
        ("DELETE", "/notes/:id", "caller-blind"),
        ("GET", "/projects/:project_id/tasks/:id", "scoped"),  # through a scoped parent
        ("DELETE", "/projects/:project_id/tasks/:id", "unchecked"),  # through an unscoped one
        ("DELETE", "/p/policy/:id", "checked"),  # Pundit: the policy compares the owner (D15)
        ("PATCH", "/p/lenient/:id", "caller-blind"),  # a policy that allows everyone
        ("GET", "/p/admin_policy/:id", "checked"),  # `user.admin? || record.user_id == user.id`
        ("DELETE", "/p/unread/:id", "unknown"),  # no TaskPolicy to read (D15)
        ("GET", "/p/scope/:id", "scoped"),  # `policy_scope` narrowing by the user
        ("GET", "/p/open_scope/:id", "caller-blind"),  # `scope.all`
        ("DELETE", "/chores/:id", "checked"),  # CanCanCan: `can :destroy, Chore, user_id: …`
        ("PATCH", "/chores/:id", "caller-blind"),  # `can :update, Chore` for anyone
        ("DELETE", "/errands/:id", "unknown"),  # a model we can't name: its Ability unread (D15)
        ("GET", "/who/open/:id", "n/a"),  # no authenticating callback
        ("GET", "/who/forged/:id", "caller-blind"),  # `@current_user` set from params
        ("GET", "/who/session_ivar/:id", "scoped"),  # an ivar set from the session (D17)
        ("GET", "/who/param_ivar/:id", "caller-blind"),  # an ivar set from params
        ("GET", "/who/own_current_user/:id", "caller-blind"),  # an app `current_user` from params
        ("DELETE", "/admin/notes/:id", "n/a"),  # an admin gate that refuses non-admins
        ("DELETE", "/admin/reports/:id", "caller-blind"),  # an admin-named callback that doesn't
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
    evidence = _row(app, "DELETE", "/notes/:id")["ownership_evidence"]
    assert (evidence["record_type"], evidence["owner_field"]) == ("Note", "user_id")


# Invented Rails apps from an independent review: code credited as protected while another
# user's record stays reachable (each must stay judged or unknown), beside protected twins.
_REVIEW = Path(__file__).parents[2] / "fixtures/code_facts/rails_ownership_review.json"
_CASES = json.loads(_REVIEW.read_text())


@pytest.mark.parametrize(
    ("case", "method", "pattern", "ownership"),
    [(c["case"], e["method"], e["pattern"], e["ownership"]) for c in _CASES for e in c["expect"]],
)
def test_holes_a_review_found_stay_closed(
    tmp_path: Path, case: str, method: str, pattern: str, ownership: str
) -> None:
    files = next(c["files"] for c in _CASES if c["case"] == case)
    assert _row(_tree(tmp_path, files), method, pattern)["ownership"] == ownership


AUTH = {
    **MODELS,
    "db/schema.rb": SCHEMA,
    "config/routes.rb": """
        Rails.application.routes.draw do
          resources :sessions, only: [:show, :destroy]
          resources :tokens, only: [:show]
        end
    """,
    "app/controllers/concerns/token_auth.rb": """
        module TokenAuth
          def authenticate_token!
            token = request.headers[:api_access_token]
            @access_token = AccessToken.find_by(token: token)
            head :unauthorized and return if @access_token.blank?
            @resource = @access_token.owner
            Current.user = @resource
          end
        end
    """,
    "app/controllers/application_controller.rb": """
        class ApplicationController < ActionController::Base
          before_action :authenticate_user!
          before_action :set_current_user
          before_action :current_account

          private

          def set_current_user
            @user ||= current_user
            Current.user = @user
          end

          def current_account
            @current_account ||= params[:account_id]
          end
        end
    """,
    "app/controllers/sessions_controller.rb": """
        class SessionsController < ApplicationController
          def destroy
            current_user.notes.find(params[:id]).destroy
          end

          def show
            Current.user.notes.find(params[:id])
          end
        end
    """,
    "app/controllers/tokens_controller.rb": """
        class TokensController < ActionController::Base
          include TokenAuth
          before_action :authenticate_token!

          def show
            Current.user.notes.find(params[:id])
          end
        end
    """,
}


@pytest.mark.parametrize(
    ("method", "pattern"),
    [
        # callbacks setting `Current.user` from the signed-in user and `@current_account`
        # from params: only the account is the request's choice (D17)
        ("DELETE", "/sessions/:id"),
        ("GET", "/sessions/:id"),
        # `Current.user` from a looked-up token (D20)
        ("GET", "/tokens/:id"),
    ],
)
def test_callbacks_that_set_the_caller_from_a_credential_keep_it(
    tmp_path: Path, method: str, pattern: str
) -> None:
    assert _row(_tree(tmp_path, AUTH), method, pattern)["ownership"] == "scoped"


@pytest.mark.parametrize(
    ("read", "ownership"),
    [
        # D20 amended: a plain cookie is the client's choice; signed and encrypted ones aren't
        ("cookies[:user_id]", "caller-blind"),
        ("cookies.signed[:user_id]", "scoped"),
        ("cookies.encrypted[:user_id]", "scoped"),
    ],
)
def test_only_a_tamper_proof_cookie_names_the_caller(
    tmp_path: Path, read: str, ownership: str
) -> None:
    files = {
        **MODELS,
        "db/schema.rb": SCHEMA,
        "config/routes.rb": (
            "Rails.application.routes.draw do\n  resources :notes, only: [:show]\nend\n"
        ),
        "app/controllers/notes_controller.rb": (
            "class NotesController < ActionController::Base\n"
            "  before_action :authenticate\n\n"
            "  def show\n    @user.notes.find(params[:id])\n  end\n\n  private\n\n"
            f"  def authenticate\n    @user = User.find_by(id: {read})\n"
            "    head :unauthorized unless @user\n  end\nend\n"
        ),
    }
    assert _row(_tree(tmp_path, files), "GET", "/notes/:id")["ownership"] == ownership


def _notes_app(controller: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    """An app whose `NotesController` destroys a note: `controller` is its body."""
    return {
        **MODELS,
        "db/schema.rb": SCHEMA,
        "config/routes.rb": (
            "Rails.application.routes.draw do\n  resources :notes, only: [:destroy]\nend\n"
        ),
        "app/controllers/application_controller.rb": (
            "class ApplicationController < ActionController::Base\n"
            "  include Pundit::Authorization\n  before_action :authenticate_user!\nend\n"
        ),
        "app/controllers/notes_controller.rb": controller,
        **(extra or {}),
    }


OWNER_CHECK = """
  before_action :set_note
  before_action :require_owner

  def destroy
    @note.destroy
  end

  private

  def set_note
    @note = Note.find(params[:id])
  end
"""


@pytest.mark.parametrize(
    ("controller", "extra", "ownership"),
    [
        # a `current_user` helper returning an ivar the request picks is no caller
        (
            "class NotesController < ApplicationController\n"
            "  before_action :load_user\n\n"
            "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\n\n"
            "  private\n\n"
            "  def load_user\n    @user = User.find(params[:user_id])\n  end\n\n"
            "  def current_user\n    @user\n  end\nend\n",
            {},
            "caller-blind",
        ),
        # an alias copies the no-op it names at that point, not a later redefinition
        (
            "class NotesController < ApplicationController\n"
            + OWNER_CHECK
            + "  def check\n  end\n  alias_method :require_owner, :check\n\n"
            "  def check\n    head :forbidden unless @note.user == current_user\n  end\nend\n",
            {},
            "caller-blind",
        ),
        # `define_method(:x, proc {})` replaces the refusing method with one we don't read
        (
            "class NotesController < ApplicationController\n"
            + OWNER_CHECK
            + "  def require_owner\n    head :forbidden unless @note.user == current_user\n"
            "  end\n  define_method(:require_owner, proc {})\nend\n",
            {},
            "caller-blind",
        ),
        # a class body that may define the helper itself: never the module's refusing one
        (
            "class NotesController < ApplicationController\n  include Strict\n"
            "  send(:define_method, :require_owner!) {}\n\n"
            "  def destroy\n    @note = Note.find(params[:id])\n    require_owner!\n"
            "    @note.destroy\n  end\nend\n",
            {
                "app/controllers/concerns/strict.rb": (
                    "module Strict\n  def require_owner!\n"
                    "    raise ActiveRecord::RecordNotFound unless @note.user == current_user\n"
                    "  end\nend\n"
                )
            },
            "caller-blind",
        ),
        # an `after_action`'s rescue clause acts on the record after the action refused
        (
            "class NotesController < ApplicationController\n"
            "  after_action :touch_note\n\n"
            "  def destroy\n    @note = Note.find(params[:id])\n"
            "    head :forbidden and return unless @note.user == current_user\n"
            "    @note.destroy\n  end\n\n  private\n\n"
            "  def touch_note\n    raise 'skip'\n  rescue StandardError\n"
            "    @note.update!(body: '')\n  end\nend\n",
            {},
            "unchecked",
        ),
        # `after_action :require_owner` replaces no `before_action :require_owner`
        (
            "class NotesController < ApplicationController\n"
            + OWNER_CHECK
            + "  after_action :require_owner\n\n"
            "  def require_owner\n    head :forbidden unless @note.user == current_user\n"
            "  end\nend\n",
            {},
            "checked",
        ),
    ],
    ids=[
        "caller-helper-ivar",
        "alias-binds-early",
        "define-method-callable",
        "dynamic-class-first",
        "after-action-rescue",
        "after-action-kind",
    ],
)
def test_what_qodo_found_stays_closed(
    tmp_path: Path, controller: str, extra: dict[str, str], ownership: str
) -> None:
    result = _tree(tmp_path, _notes_app(controller, extra))
    assert _row(result, "DELETE", "/notes/:id")["ownership"] == ownership


def test_namespaced_policies_sharing_a_short_name_are_told_apart(tmp_path: Path) -> None:
    # Pundit runs `NotePolicy` (anyone may destroy); `Zeta::NotePolicy` compares the owner
    controller = (
        "class NotesController < ApplicationController\n"
        "  def destroy\n    @note = Note.find(params[:id])\n    authorize @note\n"
        "    @note.destroy\n  end\nend\n"
    )
    extra = {
        "app/policies/note_policy.rb": (
            "class NotePolicy < ApplicationPolicy\n  def destroy?\n    true\n  end\nend\n"
        ),
        "app/policies/zeta/note_policy.rb": (
            "module Zeta\n  class NotePolicy < ApplicationPolicy\n"
            "    def destroy?\n      record.user == user\n    end\n  end\nend\n"
        ),
        "app/policies/application_policy.rb": (
            "class ApplicationPolicy\n  attr_reader :user, :record\nend\n"
        ),
    }
    result = _tree(tmp_path, _notes_app(controller, extra))
    assert _row(result, "DELETE", "/notes/:id")["ownership"] == "caller-blind"


POLICY_BASE = {
    "app/policies/application_policy.rb": (
        "class ApplicationPolicy\n  attr_reader :user, :record\nend\n"
    ),
}
AUTHORIZED = (
    "class NotesController < ApplicationController\n"
    "  def destroy\n    @note = Note.find(params[:id])\n    authorize @note\n"
    "    @note.destroy\n  end\nend\n"
)


@pytest.mark.parametrize(
    ("controller", "extra", "ownership"),
    [
        # a policy alias is the permissive method it copied, not the target's later check
        (
            AUTHORIZED,
            {
                **POLICY_BASE,
                "app/policies/note_policy.rb": (
                    "class NotePolicy < ApplicationPolicy\n  def show?\n    true\n  end\n"
                    "  alias_method :destroy?, :show?\n\n"
                    "  def show?\n    record.user == user\n  end\nend\n"
                ),
            },
            "caller-blind",
        ),
        # resetting a chain of the app's own leaves the action's authentication
        (
            "class NotesController < ApplicationController\n"
            "  define_callbacks :sync\n  reset_callbacks :sync\n\n"
            "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\nend\n",
            {},
            "scoped",
        ),
        # an external admin guard that runs only for some requests isn't admin-only
        (
            "class NotesController < ApplicationController\n"
            "  before_action :authenticate_admin!, if: :strict?\n\n"
            "  def destroy\n    Note.find(params[:id]).destroy\n  end\nend\n",
            {},
            "caller-blind",
        ),
        # a user a request header names is no caller, even beside a constant token key
        (
            "class NotesController < ApplicationController\n"
            "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\n\n"
            "  private\n\n  def current_user\n"
            '    User.find_by(email: request.headers["X-Email"], token_type: "api")\n'
            "  end\nend\n",
            {},
            "caller-blind",
        ),
        # a test's class_eval adds no guard to the app's controller
        (
            "class NotesController < ActionController::Base\n"
            "  def destroy\n    Note.find(params[:id]).destroy\n  end\nend\n",
            {
                "spec/support/auth.rb": (
                    "NotesController.class_eval { before_action :authenticate_user! }\n"
                )
            },
            "n/a",
        ),
    ],
    ids=["policy-alias", "reset-other-chain", "conditional-admin", "header-user", "spec-eval"],
)
def test_what_qodos_second_review_found_stays_closed(
    tmp_path: Path, controller: str, extra: dict[str, str], ownership: str
) -> None:
    result = _tree(tmp_path, _notes_app(controller, extra))
    assert _row(result, "DELETE", "/notes/:id")["ownership"] == ownership


def test_a_header_token_lookup_still_names_the_caller(tmp_path: Path) -> None:
    controller = (
        "class NotesController < ApplicationController\n"
        "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\n\n"
        "  private\n\n  def current_user\n"
        '    AccessToken.find_by(token: request.headers["X-Token"])&.user\n  end\nend\n'
    )
    result = _tree(tmp_path, _notes_app(controller))
    assert _row(result, "DELETE", "/notes/:id")["ownership"] == "scoped"


def test_a_conditional_skip_of_the_login_guard_is_judged(tmp_path: Path) -> None:
    controller = (
        "class NotesController < ApplicationController\n"
        "  skip_before_action :authenticate_user!, if: :public_note?\n\n"
        "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\nend\n"
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["judgement_required"]
    assert "authenticate_user!" not in row["guards"]


def test_cancancan_loads_by_its_id_param_and_find_by(tmp_path: Path) -> None:
    files = {
        **_notes_app(
            "class NotesController < ApplicationController\n"
            "  load_and_authorize_resource id_param: :slug, find_by: :slug\n\n"
            "  def destroy\n    @note.destroy\n  end\nend\n"
        ),
        "config/routes.rb": (
            "Rails.application.routes.draw do\n"
            "  resources :notes, only: [:destroy], param: :slug\nend\n"
        ),
        "app/models/ability.rb": (
            "class Ability\n  include CanCan::Ability\n  def initialize(user)\n"
            "    can :destroy, Note, user_id: user.id\n  end\nend\n"
        ),
    }
    result = _tree(tmp_path, files)
    assert _row(result, "DELETE", "/notes/:slug")["ownership"] == "checked"


def test_an_irregular_table_keeps_its_owner_column(tmp_path: Path) -> None:
    files = {
        **_notes_app(
            "class NotesController < ApplicationController\n"
            "  def destroy\n    Person.find(params[:id]).destroy\n  end\nend\n"
        ),
        "app/models/person.rb": "class Person < ApplicationRecord\n  belongs_to :user\nend\n",
        "db/schema.rb": SCHEMA.replace(
            '  create_table "holidays"',
            '  create_table "people" do |t|\n    t.references "user"\n  end\n'
            '  create_table "holidays"',
        ),
    }
    row = _row(_tree(tmp_path, files), "DELETE", "/notes/:id")
    assert (row["ownership"], row["ownership_evidence"]["owner_field"]) == (
        "caller-blind",
        "user_id",
    )


def test_another_apps_model_never_lends_an_association(tmp_path: Path) -> None:
    # the host's notes are reached through memberships (never the caller's own, D18); a test
    # app's `User` holding them directly mustn't make the host's lookup scoped
    files = {
        **_notes_app(
            "class NotesController < ApplicationController\n"
            "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\nend\n"
        ),
        "app/models/user.rb": (
            "class User < ApplicationRecord\n  has_many :memberships\n"
            "  has_many :notes, through: :memberships\nend\n"
        ),
        "spec/dummy/config/routes.rb": "Rails.application.routes.draw do\nend\n",
        "spec/dummy/app/models/user.rb": "class User < ApplicationRecord\n  has_many :notes\nend\n",
    }
    row = _row(_tree(tmp_path, files), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


def test_a_block_callback_in_an_admin_named_file_is_no_admin_gate(tmp_path: Path) -> None:
    files = {
        **_notes_app("class NotesController; end\n"),
        "config/routes.rb": (
            "Rails.application.routes.draw do\n"
            "  resources :notes, only: [:destroy], controller: 'admin'\nend\n"
        ),
        "app/controllers/admin_controller.rb": (
            "class AdminController < ApplicationController\n"
            "  before_action { @started = Time.current }\n\n"
            "  def destroy\n    Note.find(params[:id]).destroy\n  end\nend\n"
        ),
    }
    assert _row(_tree(tmp_path, files), "DELETE", "/notes/:id")["ownership"] == "caller-blind"


def test_an_ability_whose_parent_adds_rules_is_unread(tmp_path: Path) -> None:
    files = _notes_app(
        "class NotesController < ApplicationController\n  load_and_authorize_resource\n\n"
        "  def destroy\n    @note.destroy\n  end\nend\n",
        {
            "app/models/base_ability.rb": (
                "class BaseAbility\n  include CanCan::Ability\n"
                "  def initialize(user)\n    can :manage, Note\n  end\nend\n"
            ),
            "app/models/ability.rb": (
                "class Ability < BaseAbility\n  include CanCan::Ability\n"
                "  def initialize(user)\n    super\n"
                "    can :destroy, Note, user_id: user.id\n  end\nend\n"
            ),
        },
    )
    assert _row(_tree(tmp_path, files), "DELETE", "/notes/:id")["ownership"] == "unknown"


@pytest.mark.parametrize(
    "refusal",
    [
        "render json: @note unless current_user.admin?",
        "render :show unless current_user.admin?",
        "redirect_to notes_path, alert: @note.body unless current_user.admin?",
    ],
)
def test_an_admin_gate_that_sends_the_record_is_none(tmp_path: Path, refusal: str) -> None:
    controller = (
        "class NotesController < ApplicationController\n"
        "  before_action :set_note\n  before_action :require_admin\n\n"
        "  def destroy\n    @note.destroy\n  end\n\n  private\n\n"
        "  def set_note\n    @note = Note.find(params[:id])\n  end\n\n"
        f"  def require_admin\n    {refusal}\n  end\nend\n"
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] not in ("n/a", "checked", "scoped", "none")


IMPERSONATED = (
    "class NotesController < ApplicationController\n"
    "  prepend_before_action :impersonate\n\n"
    "  def destroy\n    {lookup}.notes.find(params[:id]).destroy\n  end\n\n"
    "  private\n\n  def impersonate\n    {write}\n  end\n\n"
    "  def current_user\n    @current_user ||= User.find_by(id: session[:user_id])\n  end\nend\n"
)


@pytest.mark.parametrize(
    ("lookup", "write"),
    [
        ("Current.user", "Current.user = User.find(params[:user_id])"),
        ("Current.user", "Current.user ||= User.find(params[:user_id])"),
        ("Current.user", "Current.set(user: User.find(params[:user_id]))"),
        ("current_user", "self.current_user = User.find(params[:user_id])"),
        ("current_user", "session[:user_id] = params[:user_id]"),
        ("current_user", "session[:user_id] ||= params[:user_id]"),
        ("current_user", "session.update(user_id: params[:user_id])"),
        ("current_user", "session.merge!(params.permit(:user_id).to_h)"),
        ("current_user", "session.store(:user_id, params[:user_id])"),
        ("current_user", "request.session[:user_id] = params[:user_id]"),
        ("current_user", "session[key] = params[:user_id]"),
        ("current_user", "cookies.signed.permanent[:user_id] = params[:user_id]"),
    ],
)
def test_a_caller_the_request_sets_is_never_scoped(tmp_path: Path, lookup: str, write: str) -> None:
    controller = IMPERSONATED.format(lookup=lookup, write=write)
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


@pytest.mark.parametrize(
    "write",
    [
        "session[:return_to] = request.fullpath",
        "session[:user_id] = current_user.id",
    ],
)
def test_a_session_write_that_leaves_the_caller_keeps_it_scoped(tmp_path: Path, write: str) -> None:
    controller = IMPERSONATED.format(lookup="current_user", write=write)
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"


def test_a_session_write_devise_may_read_leaves_no_caller_scoped(tmp_path: Path) -> None:
    controller = (
        "class NotesController < ApplicationController\n"
        "  prepend_before_action :impersonate\n\n"
        "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\n\n"
        "  private\n\n  def impersonate\n"
        '    session["warden.user.user.key"] = [[params[:user_id]], nil]\n  end\nend\n'
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


FORGED_SESSION = (
    "class NotesController < ApplicationController\n"
    "  prepend_before_action :impersonate\n\n"
    "  def destroy\n    current_user.notes.find(params[:id]).destroy\n  end\n\n"
    "  private\n\n  def impersonate\n    {write}\n  end\n\n{helpers}end\n"
)
SESSION_USER = "  def current_user\n    @current_user ||= User.find_by(id: {read})\n  end\n"


@pytest.mark.parametrize(
    ("write", "helpers"),
    [
        # read through a method on the store
        (
            "session[:user_id] = params[:user_id]",
            SESSION_USER.format(read="session.fetch(:user_id, nil)"),
        ),
        (
            "session[:user_id] = params[:user_id]",
            SESSION_USER.format(read="session.to_h['user_id']"),
        ),
        ("session[:user_id] = params[:user_id]", SESSION_USER.format(read="session.dig(:user_id)")),
        # a caller helper that returns the lookup, assigning nothing
        (
            "session[:user_id] = params[:user_id]",
            "  def current_user\n    User.find_by(id: session[:user_id])\n  end\n",
        ),
        (
            "session[:user_id] = params[:user_id]",
            "  def current_user = User.find_by(id: session[:user_id])\n",
        ),
        # written by a helper that takes the value
        (
            "login_as(params[:user_id])",
            "  def login_as(id)\n    session[:user_id] = id\n  end\n\n"
            + SESSION_USER.format(read="session[:user_id]"),
        ),
        # written through an alias, a block, `self` or `send`
        (
            "s = session\n    s[:user_id] = params[:user_id]",
            SESSION_USER.format(read="session[:user_id]"),
        ),
        (
            "session.tap { |s| s[:user_id] = params[:user_id] }",
            SESSION_USER.format(read="session[:user_id]"),
        ),
        (
            "self.session[:user_id] = params[:user_id]",
            SESSION_USER.format(read="session[:user_id]"),
        ),
        (
            "session.send(:[]=, :user_id, params[:user_id])",
            SESSION_USER.format(read="session[:user_id]"),
        ),
        # a local named `session` in another method shadows nothing here
        (
            "session[:user_id] = params[:user_id]\n    current_session",
            "  def current_session\n"
            "    session = Session.find_by(id: cookies.signed[:sid])\n  end\n\n"
            + SESSION_USER.format(read="session[:user_id]"),
        ),
    ],
)
def test_every_way_the_request_reaches_the_sessions_caller_is_closed(
    tmp_path: Path, write: str, helpers: str
) -> None:
    controller = FORGED_SESSION.format(write=write, helpers=helpers)
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


@pytest.mark.parametrize(
    ("write", "read"),
    [
        (
            "session[:user_id] = nil if session[:expires_at].to_i < Time.now.to_i",
            "session[:user_id]",
        ),
        (
            "cookies.permanent.signed[:user_id] = { value: current_user.id, httponly: true }",
            "cookies.signed[:user_id]",
        ),
        ("session[:a], session[:b] = 1, 2", "session[:user_id]"),
        ("key = :return_to\n    session[key] = request.fullpath", "session[:user_id]"),
        ("session.delete(:user_id)", "session[:user_id]"),
    ],
)
def test_a_session_write_the_request_doesnt_choose_keeps_the_caller(
    tmp_path: Path, write: str, read: str
) -> None:
    controller = FORGED_SESSION.format(write=write, helpers=SESSION_USER.format(read=read))
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"


def test_a_namespace_whose_module_the_version_decides_is_unknown(tmp_path: Path) -> None:
    files = {
        **_notes_app(
            "class NotesController < ApplicationController\n  def destroy\n"
            "    current_user.notes.find(params[:id]).destroy\n  end\nend\n"
        ),
        "config/routes.rb": (
            "Rails.application.routes.draw do\n  namespace :admin, module: nil do\n"
            "    resources :notes, only: [:destroy]\n  end\nend\n"
        ),
        "app/controllers/admin/notes_controller.rb": (
            "class Admin::NotesController < ApplicationController\n  def destroy\n"
            "    Note.find(params[:id]).destroy\n  end\nend\n"
        ),
    }
    assert _row(_tree(tmp_path, files), "DELETE", "/admin/notes/:id")["ownership"] == "unknown"


# Invented session and caller-setter shapes from two independent reviews: each file set is
# what differs from `_notes_app("")`. A request-chosen caller stays judged or unknown.
_SESSION = Path(__file__).parents[2] / "fixtures/code_facts/rails_session_review.json"
_SESSION_CASES = json.loads(_SESSION.read_text())


@pytest.mark.parametrize("case", _SESSION_CASES, ids=[c["case"] for c in _SESSION_CASES])
def test_what_the_session_reviews_found_stays_closed(tmp_path: Path, case: dict) -> None:
    files = {**_notes_app(""), **case["files"]}
    row = _row(_tree(tmp_path, files), case["method"], case["pattern"])
    assert row["ownership"] == case["ownership"], case["why"]


@pytest.mark.parametrize(
    "write",
    [
        "session.values.first.replace(params[:user_id])",
        "session.to_h[:user_id].replace(params[:user_id])",
        "session[:user_id].to_s.replace(params[:user_id])",
        "session.each_value { |v| v.replace(params[:user_id]) }",
    ],
)
def test_a_stored_value_mutated_through_a_read_is_a_write(tmp_path: Path, write: str) -> None:
    controller = FORGED_SESSION.format(
        write=write, helpers=SESSION_USER.format(read="session[:user_id]")
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


def test_another_objects_session_is_not_the_requests(tmp_path: Path) -> None:
    write = "@account = Account.first\n    @account.session.update(token: params[:t])"
    controller = FORGED_SESSION.format(
        write=write, helpers=SESSION_USER.format(read="session[:user_id]")
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"


def test_a_local_named_like_a_helper_calls_no_helper(tmp_path: Path) -> None:
    controller = FORGED_SESSION.format(
        write='helper = "safe"\n    logger.info(helper)',
        helpers="  def helper\n    session[:user_id] = params[:user_id]\n  end\n\n"
        + SESSION_USER.format(read="session[:user_id]"),
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"


def test_a_cycle_of_key_locals_in_a_loop_ends(tmp_path: Path) -> None:
    write = (
        "a = :x\n    b = :y\n    2.times do\n      a = b\n      b = a\n"
        "      session[a] = params[:user_id]\n    end"
    )
    controller = FORGED_SESSION.format(
        write=write, helpers=SESSION_USER.format(read="session[:user_id]")
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


@pytest.mark.parametrize(
    ("write", "helpers"),
    [
        # the request through a local (`r = request`), or the store handed to a helper
        ("r = request\n    r.session[:user_id] = params[:user_id]", ""),
        (
            "remember(session)",
            "  def remember(session)\n    session[:user_id] = params[:id]\n  end\n\n",
        ),
        # a block assigning the outer key local
        ("key = :locale\n    [1].each { key = :user_id }\n    session[key] = params[:user_id]", ""),
        # `delete` returns the value it removes
        ("session[:pending_uid] = params[:uid]", ""),
        # signing in through `self` or `send`
        ("self.sign_in(User.find(params[:user_id]))", ""),
        ("send(:sign_in, User.find(params[:user_id]))", ""),
    ],
    ids=[
        "request-alias",
        "session-param",
        "block-key",
        "delete-read",
        "self-sign-in",
        "send-sign-in",
    ],
)
def test_what_qodos_review_of_362_found_stays_closed(
    tmp_path: Path, write: str, helpers: str
) -> None:
    read = "session.delete(:pending_uid)" if "pending_uid" in write else "session[:user_id]"
    controller = FORGED_SESSION.format(
        write=write, helpers=helpers + SESSION_USER.format(read=read)
    )
    if "sign_in" in write:
        controller = FORGED_SESSION.format(write=write, helpers="")
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


def test_a_method_an_action_defines_but_never_calls_runs_nothing(tmp_path: Path) -> None:
    controller = FORGED_SESSION.format(
        write="def later\n      session[:user_id] = params[:user_id]\n    end",
        helpers=SESSION_USER.format(read="session[:user_id]"),
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"


def test_a_name_read_before_its_assignment_in_a_loop_is_the_method(tmp_path: Path) -> None:
    write = "2.times do\n      forge\n      forge = 1\n    end"
    controller = FORGED_SESSION.format(
        write=write,
        helpers="  def forge\n    session[:user_id] = params[:user_id]\n  end\n\n"
        + SESSION_USER.format(read="session[:user_id]"),
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


def test_a_method_an_action_defines_and_calls_runs(tmp_path: Path) -> None:
    write = "def later\n      session[:user_id] = params[:user_id]\n    end\n    later"
    controller = FORGED_SESSION.format(
        write=write, helpers=SESSION_USER.format(read="session[:user_id]")
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] != "scoped"


@pytest.mark.parametrize(
    "write",
    [
        # another object's session, through a helper's parameter
        "touch(Account.first)\n  end\n\n"
        "  def touch(account)\n    account.session.update(token: params[:t])",
        # a block's own parameter isn't the outer key
        "key = :return_to\n    [1].each { |key| key = params[:user_id] }\n"
        "    session[key] = request.fullpath",
    ],
    ids=["helper-param-session", "shadowed-key"],
)
def test_what_qodos_third_review_of_362_keeps_scoped(tmp_path: Path, write: str) -> None:
    controller = FORGED_SESSION.format(
        write=write, helpers=SESSION_USER.format(read="session[:user_id]")
    )
    row = _row(_tree(tmp_path, _notes_app(controller)), "DELETE", "/notes/:id")
    assert row["ownership"] == "scoped"
