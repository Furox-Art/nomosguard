"""Fail CI if any collected tests are skipped; a skip is not a passing gate."""


def pytest_sessionfinish(session, exitstatus):
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return
    skipped = reporter.stats.get("skipped", ())
    if skipped:
        reporter.write_sep("!", f"QUALITY GATE FAILED: {len(skipped)} skipped test(s)")
        session.exitstatus = 1
