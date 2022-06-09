import torch

class Conf():
    def __init__(self) -> None:
        self.USE_GPU = True
        self.DEBUG = True
        self.device = torch.device("cuda:0")

conf = Conf()