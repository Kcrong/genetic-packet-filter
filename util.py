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

    return wrapper()
