import os


class Logging:
    """
    If you don't give 'filename' parameter,
    filename will be caller's filename.
    :example:
        main.py
            logger = Logging()

        $ ls
        main.py main.log
    """
    def __init__(self, filename=None):
        if filename is None:
            filename = self.__find_caller() + '.log'

        self.filename = filename
        self.file_handler = open(filename, 'a')

    def __write_data(self, data):
        self.file_handler.write(data)

    def log(self, data):
        """
        Save log with data
        :param data: data to write
        :return: void
        """
        self.__write_data(data)

    def p_log(self, data):
        """
        Save log with data, and print
        :param data: data to write & print
        :return: void
        """
        print data
        self.__write_data(data)

    @staticmethod
    def __find_caller():
        import inspect
        caller = inspect.getouterframes(inspect.currentframe(), 2)[2][1]
        return os.path.basename(caller).split('.')[0]  # Remove type string

    def __del__(self):
        self.file_handler.close()

    def __repr__(self):
        return "<Logger %s>" % self.filename
