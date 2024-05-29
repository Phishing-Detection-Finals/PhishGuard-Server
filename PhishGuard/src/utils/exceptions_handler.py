from functools import wraps
from typing import Dict, Type
from flask import jsonify
from http import HTTPStatus


class ExceptionsHandler:
    @staticmethod
    def handle_exceptions(exception_registry: Dict[Type[Exception], HTTPStatus]):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except tuple(exception_registry.keys()) as e:
                    for exc_type in exception_registry.keys():
                        if isinstance(e, exc_type):
                            # handles subclasses exceptions aswell
                            return jsonify({"error": str(e)}), exception_registry[exc_type]

                except Exception as e:
                    return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR
            return wrapper
        return decorator
