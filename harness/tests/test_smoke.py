import eval_suite


def test_package_importable():
    assert eval_suite.__version__ == "0.1.0"
