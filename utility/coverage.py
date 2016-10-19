def counter(func):
    """
    Decorator For count Func Calling
    :return: void. Just func.called
    :example:

        @counter
        def foo():
            ~some~code~

        print foo.called

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
    :example:

        @timer
        def bar():
            ~some~code~

        print bar.exec_time

    """

    def wrapper(*args, **kwargs):
        import time

        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        wrapper.exec_time = (end - start)

        return result

    wrapper.__name__ = func.__name__

    return wrapper


class Counter:
    """
    Just make object, and print.
    :example:

        cnt = Counter()
        for i in range(0, 3):
            print cnt

        $ python main.py
        1
        2
        3

    """
    def __init__(self):
        self.count = 0

    def __repr__(self):
        self.count += 1
        return str(self.count)

    def __str__(self):
        return self.__repr__()

    def reset(self):
        self.__init__()
