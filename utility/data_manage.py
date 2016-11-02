def remove_dup(data):
    """
    :param data: data set (list)
    :return: list that Removed-dup data
    """
    return list(set(data))


def is_iterable(data):
    if type(data) != str and hasattr(data, '__iter__'):
        return True
    else:
        return False


def return2type(type2change):
    """
    Change return data's type
    :param type2change: Type to Change
    :return: changed data
    :example:

        @return2type(list)
        def foo():
            a = set()
            return a

        data = foo()
        assert type(data) == list

        # it is working with custom type

        def custom_type(data):
            return [_ for _ in data if _ != 'dummy']

        @return2type(custom_type)
        def bar():
            a = list('it', 'is', 'dummy')
            return a

        data = bar()
        assert data == ['it', 'is']
    """

    def real_deco(func):
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            result_type = type(result)

            return result_type([type2change(data) for data in result])

        return wrapper

    return real_deco


def remove_dup_by_key(dup_data_list, key):
    key_list = list()
    data_list = list()

    for data in dup_data_list:
        if key(data) not in key_list:
            data_list.append(data)
            key_list.append(key(data))
    return data_list
