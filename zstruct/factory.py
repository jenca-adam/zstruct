from . import field


def make_signed(size, endian, name=None):
    if name is None:
        name = f"I{size*8}{endian.value.upper()}"

    class _(field.SignedIntegerField):
        __qualname__ = name
        __name__ = name
        SIZE = size
        ENDIAN = endian

    return _


def make_unsigned(size, endian, name=None):
    if name is None:
        name = f"U{size*8}{endian.value.upper()}"

    class _(field.UnsignedIntegerField):
        __qualname__ = name
        __name__ = name
        SIZE = size
        ENDIAN = endian

    return _


def make_string(size_field, name=None):
    if name is None:
        name = f"S{size_field.size*8}"

    class _(field.StringField):
        __qualname__ = name
        __name__ = name
        SIZE_FIELD = size_field

    return _


def make_array(element_field, length, name=None):
    if name is None:
        name = element_field.__name__ + f"x{length}"

    class _(field.ArrayField):
        __qualname__ = name
        __name__ = name
        ELEMENT_FIELD = element_field
        LENGTH = length

    return _


def make_var_array(element_field, length_field, name=None):
    if name is None:
        name = element_field.__name__ + f"@{length_field.__name__}"

    class _(field.VarArrayField):
        __qualname__ = name
        __name__ = name
        ELEMENT_FIELD = element_field
        LENGTH_FIELD = length_field

    return _


def make_struct(struct_dict, name=None):
    if name is None:
        name = "STRUCTURE"

    class _(field.StructField):
        __qualname__ = name
        __name__ = name
        STRUCT = struct_dict

    return _


def struct(cls):
    return make_struct(cls.__annotations__)
