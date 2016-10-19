import os


class Logging:
    def __init__(self, filename=None):
        if filename is None:
            filename = self.__find_caller() + '.log'

        self.filename = filename
        self.file_handler = open(filename, 'a')

    def __write_data(self, data):
        self.file_handler.write(data)

    def log(self, data):
        self.__write_data(data)

    def p_log(self, data):
        print data
        self.__write_data(data)

    @staticmethod
    def __find_caller():
        import inspect
        caller = inspect.getouterframes(inspect.currentframe(), 2)[2][1]
        return os.path.basename(caller).split('.')[0]  # Remove type string

    def __del__(self):
        self.file_handler.close()
