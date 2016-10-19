import os


class Logging:
    def __init__(self, filename=None):
        if filename is None:
            filename = os.path.basename(__file__).split('.')[0] + '.log'

        self.filename = filename
        self.filehandler = open(filename, 'a')

    def __write_data(self, data):
        self.filehandler.write(data)

    def log(self, data):
        self.__write_data(data)

    def p_log(self, data):
        print data
        self.__write_data(data)

    def __del__(self):
        self.filehandler.close()
