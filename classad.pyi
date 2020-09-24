# stubs for classad
# TODO These should be moved to the Python bindings for HTCondor itself

from typing import Any

class ExprTree(object): ...

class ClassAd(dict):
    def printJson(self) -> str: ...
    def flatten(self, expr: ExprTree) -> Any: ...
