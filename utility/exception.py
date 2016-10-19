# original at python3 - contextlib.suppress


class ignore:
    def __init__(self, *exceptions):
        self._exceptions = exceptions

    def __enter__(self):
        pass

    def __exit__(self, exception_type, *_):
        return exception_type is not None and issubclass(exception_type, self._exceptions)
