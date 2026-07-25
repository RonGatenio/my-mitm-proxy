import importlib.util, os

_spec = importlib.util.spec_from_file_location(
    "report", os.path.join(os.path.dirname(__file__), "report.py"))
report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report)


def test_status_pass_when_match():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "2", "srcip": "ok"}
    assert report.status_for(exp, act) == "PASS"


def test_status_fail_on_forward_mismatch():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "fail", "act_dump": "ok", "act_level": "2", "srcip": "ok"}
    assert report.status_for(exp, act) == "FAIL"


def test_expected_fail_is_pass():
    exp = {"exp_fwd": "fail", "exp_dump": "na", "exp_level": "0"}
    act = {"act_fwd": "fail", "act_dump": "na", "act_level": "0", "srcip": "na"}
    assert report.status_for(exp, act) == "PASS"


def test_level_floor_enforced():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "1", "srcip": "ok"}
    assert report.status_for(exp, act) == "FAIL"


def test_boxleak_fails():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "ok", "act_dump": "ok", "act_level": "2", "srcip": "BOXLEAK"}
    assert report.status_for(exp, act) == "FAIL"


def test_skip_is_skip():
    exp = {"exp_fwd": "ok", "exp_dump": "ok", "exp_level": "2"}
    act = {"act_fwd": "skip", "act_dump": "skip", "act_level": "0", "srcip": ""}
    assert report.status_for(exp, act) == "SKIP"
