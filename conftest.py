"""Repo-wide pytest configuration, applied to both tests/ and plugins/.

Plugins and the shell write artifacts to $EVENTMILL_WORKSPACE/artifacts and
fall back to ./workspace when it is unset. A test that forgot to redirect it
wrote fixture output into the operator's real artifact directory, where it read
as genuine projections — more than 140 such files had accumulated before this
existed.
Every test now gets a throwaway workspace; a test that sets its own still wins.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolated_workspace(tmp_path_factory, monkeypatch):
    workspace = tmp_path_factory.mktemp("workspace")
    monkeypatch.setenv("EVENTMILL_WORKSPACE", str(workspace))
    return workspace
