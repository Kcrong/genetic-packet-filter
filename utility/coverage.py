def counter(func):
    """
    Decorator For count Func Calling
    :return: void. Just func.called
    """

    def wrapper(*args, **kwargs):
        wrapper.called += 1
        return func(*args, **kwargs)

    wrapper.called = 0
    wrapper.__name__ = func.__name__

    return wrapper


def timer(func):
    """
    Print Exec time
    :return: void. Just print exec time by stdout
    """

    def wrapper(*args, **kwargs):
        import time

        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()

        print "%s : %f" % (func.__name__, (end - start))

        return result

    return wrapper


class Counter:
    def __init__(self):
        self.count = 0

    def __repr__(self):
        self.count += 1
        return str(self.count)

    def __str__(self):
        return self.__repr__()

    def reset(self):
        self.__init__()
