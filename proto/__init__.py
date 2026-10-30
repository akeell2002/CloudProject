import os
import sys

# Allows proto files to resolve imports cleanly
sys.path.append(os.path.dirname(__file__))

from . import fedconsensus_pb2 as pb2
from . import fedconsensus_pb2_grpc as pb2_grpc

__all__ = ["pb2", "pb2_grpc"]