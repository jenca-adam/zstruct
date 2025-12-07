import struct
import io
from .enums import Endian
from .util import classproperty


class FieldMeta(type):
    def __getitem__(cls, length):
        from .factory import make_array

        return make_array(cls, length)


class Field(metaclass=FieldMeta):
    """
    A generic field class.
    Should be subclassed.
    Implement parse(), unparse() and size().
    Optionally, implement _check()
    """

    ARG_TYPE = None

    def __init__(self, value):
        err = self.__class__._check(value)
        if err:
            err = err.__class__(f"{self.__class__.__qualname__}: {str(err)}")
            raise err
        self.value = value

    def __repr__(self):
        return f"{self.__class__.__qualname__}({self.value})"

    @classmethod
    def check(cls, value):
        rng = cls._range
        if cls._arg_type is not None:
            if not isinstance(value, cls._arg_type):
                return TypeError(
                    f"expected value of type {cls._arg_type.__name__} got {value.__class__.__name__}"
                )
        if rng and value not in rng:
            return OverflowError(f"argument must be in {rng}")
        return cls._check(value)

    @classmethod
    def _check(cls, value):
        pass

    @classmethod
    def parse(cls, stream):
        raise NotImplementedError

    def unparse(self, stream):
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, buf):
        return cls.parse(io.BytesIO(buf))

    def to_bytes(self):
        bytes_io = io.BytesIO()
        self.unparse(bytes_io)
        return bytes_io.getvalue()

    @classproperty
    def size(cls):
        raise TypeError(f"{cls.__qualname__} has unknown size")

    @classproperty
    def _range(cls):
        return None

    @classproperty
    def _arg_type(cls):
        return None


class SizedField(Field):
    """
    A generic constant size field class.
    Should be subclassed.
    Implement _from_bytes(), to_bytes() and size()
    """

    SIZE = None

    @classmethod
    def parse(cls, stream):
        if cls.SIZE is None:
            raise NotImplementedError
        data = stream.read(cls.SIZE)
        return cls.from_bytes(data)

    def unparse(self, stream):
        stream.write(self.to_bytes())

    @classmethod
    def _from_bytes(cls, buf):
        raise NotImplementedError

    @classmethod
    def from_bytes(cls, buf):
        if cls.SIZE is None:
            raise NotImplementedError
        if len(buf) != cls.SIZE:
            raise ValueError(
                f"{cls.__qualname__}.from_bytes() expected a buffer of {cls.size} bytes, got {len(buf)}"
            )
        return cls._from_bytes(buf)

    def to_bytes(self):
        raise NotImplementedError

    @classproperty
    def size(cls):
        raise NotImplementedError


class SingleStructField(SizedField):
    """
    A generic single struct field class.
    Overwrite STRUCT, should be a struct string containing a single field.
    """

    STRUCT = None

    @classmethod
    def _check(cls, value):
        try:
            struct.pack(cls.STRUCT, value)
        except struct.error as e:
            return e

    @classmethod
    def _from_bytes(cls, buf):
        if cls.STRUCT is None:
            raise NotImplementedError
        return cls(struct.unpack(cls.STRUCT, buf)[0])

    def to_bytes(self):
        if cls.STRUCT is None:
            raise NotImplementedError
        return struct.pack(cls.STRUCT, self.value)

    @classproperty
    def size(cls):
        if cls.STRUCT is None:
            raise NotImplementedError
        return struct.calcsize(cls.STRUCT)


class MultiStructField(SizedField):
    """
    A generic multi struct field class.
    Overwrite STRUCT, should be a struct string.
    """

    STRUCT = None

    @classmethod
    def _check(cls, value):
        try:
            struct.pack(cls.STRUCT, value)
        except struct.error as e:
            return e

    @classmethod
    def from_bytes(cls, buf):
        if cls.STRUCT is None:
            raise NotImplementedError
        return cls(struct.unpack(cls.STRUCT, buf))

    def to_bytes(self):
        if cls.STRUCT is None:
            raise NotImplementedError
        return struct.pack(cls.STRUCT, self.value)

    @classproperty
    def size(cls):
        if cls.STRUCT is None:
            raise NotImplementedError
        return struct.calcsize(cls.STRUCT)


class UnsignedIntegerField(SizedField):
    """
    A generic fixed size unsigned integer field class.
    Overwrite SIZE - should be an int and ENDIAN - should be an enums.Endian member
    """

    SIZE = None
    ENDIAN = None

    @classmethod
    def _from_bytes(cls, buf):
        if cls.SIZE is None or cls.ENDIAN is None:
            raise NotImplementedError
        return cls(int.from_bytes(buf, cls.ENDIAN.value))

    def to_bytes(self):
        if self.SIZE is None or self.ENDIAN is None:
            raise NotImplementedError

        return self.value.to_bytes(self.size, self.ENDIAN.value)

    @classproperty
    def size(cls):
        if cls.SIZE is None or cls.ENDIAN is None:
            raise NotImplementedError
        return cls.SIZE

    @classproperty
    def _range(cls):
        return range((1 << (cls.SIZE * 8)))
    
    @classproperty
    def _arg_type(cls):
        return int

class SignedIntegerField(SizedField):
    """
    A generic fixed size signed integer field class.
    Overwrite SIZE - should be an int and ENDIAN - should be an enums.Endian member
    """

    SIZE = None
    ENDIAN = None

    @classmethod
    def _from_bytes(cls, buf):
        if cls.SIZE is None or cls.ENDIAN is None:
            raise NotImplementedError
        sign_bit = 1 << (cls.SIZE * 8 - 1)
        val = int.from_bytes(buf, cls.ENDIAN.value)
        return cls((val ^ sign_bit) - sign_bit)

    def to_bytes(self):
        if self.SIZE is None or self.ENDIAN is None:
            raise NotImplementedError
        val = self.value & ((1 << (self.SIZE * 8)) - 1)
        return val.to_bytes(self.size, self.ENDIAN.value)

    @classproperty
    def size(cls):
        if cls.SIZE is None or cls.ENDIAN is None:
            raise NotImplementedError
        return cls.SIZE

    @classproperty
    def _range(cls):
        return range(-(1 << (cls.SIZE * 8 - 1)), (1 << (cls.SIZE * 8 - 1)))
    
    @classproperty
    def _arg_type(cls):
        return int

class StringField(Field):
    """
    A generic field that contains size of a string, followed by the string itself.
    Should be subclassed.
    Overwrite SIZE_FIELD - a Field subclass to be used for the size.
    """

    SIZE_FIELD = None

    @classmethod
    def _check(cls, value):
        if cls.SIZE_FIELD is None:
            raise NotImplementedError
        return cls.SIZE_FIELD.check(len(value))

    @classmethod
    def parse(cls, stream):
        if cls.SIZE_FIELD is None:
            raise NotImplementedError
        size = cls.SIZE_FIELD.parse(stream).value
        data = stream.read(size)
        if len(data) < size:
            raise ValueError(
                f"{cls.__qualname__}.parse() expected a buffer of {size} bytes (size), got {len(data)}"
            )
        return cls(data)

    def unparse(self, stream):
        if self.SIZE_FIELD is None:
            raise NotImplementedError

        self.SIZE_FIELD(len(self.value)).unparse(stream)
        stream.write(self.value)

    @classproperty
    def _arg_type(cls):
        return bytes


class ZeroTerminated(Field):
    """
    A string field terminated by a zero byte.
    """

    @classmethod
    def _check(cls, value):
        if 0 in value:
            return ValueError("zero byte in zero terminated string")

    @classmethod
    def parse(cls, stream):
        res = bytearray()
        while True:
            b = stream.read(1)
            if not b:
                raise EOFError("EOF while reading a zero terminated string")
            if b == b"\0":
                break
            res.append(ord(b))
        return cls(bytes(res))

    def unparse(self, stream):
        stream.write(self.value)
        stream.write(b"\x00")

    @classproperty
    def _arg_type(self):
        return bytes


class ArrayField(Field):
    """
    A generic field that contains a fixed number of other fields of one type.
    """

    ELEMENT_FIELD = None
    LENGTH = None

    @classmethod
    def _check(cls, value):
        for item in value:
            err = cls.ELEMENT_FIELD.check(item)
            if err:
                return err
        return (
            TypeError(f"expected value of length {cls.LENGTH}, got {len(value)}")
            if len(value) != cls.LENGTH
            else None
        )

    @classmethod
    def parse(cls, stream):
        if cls.LENGTH is None or cls.ELEMENT_FIELD is None:
            raise NotImplementedError
        arr = []
        for i in range(cls.LENGTH):
            arr.append(cls.ELEMENT_FIELD.parse(stream).value)
        return cls(arr)

    def unparse(self, stream):
        for item in self.value:
            self.ELEMENT_FIELD(item).unparse(stream)

    @classproperty
    def size(cls):
        if cls.LENGTH is None or cls.ELEMENT_FIELD is None:
            raise NotImplementedError
        return cls.ELEMENT_FIELD.size * cls.LENGTH

    @classproperty
    def _arg_type(cls):
        return list


class VarArrayField(Field):
    """
    A generic field that contains a variable number of other fields of one type.
    The length prefixes the array data.
    """

    ELEMENT_FIELD = None
    LENGTH_FIELD = None

    @classmethod
    def _check(cls, value):
        if cls.LENGTH_FIELD is None or cls.ELEMENT_FIELD is None:
            raise NotImplementedError
        for item in value:
            err = cls.ELEMENT_FIELD.check(item)
            if err:
                return err.__class__(f"value: {str(err)}")
        err = cls.LENGTH_FIELD.check(len(value))
        if err:
            return err.__class__(f"size: {str(err)}")

    @classmethod
    def parse(cls, stream):
        if cls.LENGTH_FIELD is None or cls.ELEMENT_FIELD is None:
            raise NotImplementedError
        arr = []
        length = cls.LENGTH_FIELD.parse(stream).value
        for i in range(length):
            arr.append(cls.ELEMENT_FIELD.parse(stream).value)
        return cls(arr)

    def unparse(self, stream):
        self.LENGTH_FIELD(len(self.value)).unparse(stream)
        for item in self.value:
            self.ELEMENT_FIELD(item).unparse(stream)

    @classproperty
    def _arg_type(cls):
        return list


class U8(UnsignedIntegerField):
    SIZE = 1
    ENDIAN = Endian.LITTLE


class I8(SignedIntegerField):
    SIZE = 1
    ENDIAN = Endian.LITTLE


class U16LE(UnsignedIntegerField):
    SIZE = 2
    ENDIAN = Endian.LITTLE


class U16BE(UnsignedIntegerField):
    SIZE = 2
    ENDIAN = Endian.BIG


class I16LE(SignedIntegerField):
    SIZE = 2
    ENDIAN = Endian.LITTLE


class I16BE(SignedIntegerField):
    SIZE = 2
    ENDIAN = Endian.BIG


class U32LE(UnsignedIntegerField):
    SIZE = 4
    ENDIAN = Endian.LITTLE


class U32BE(UnsignedIntegerField):
    SIZE = 4
    ENDIAN = Endian.BIG


class I32LE(SignedIntegerField):
    SIZE = 4
    ENDIAN = Endian.LITTLE


class I32BE(SignedIntegerField):
    SIZE = 4
    ENDIAN = Endian.BIG


class U64LE(UnsignedIntegerField):
    SIZE = 8
    ENDIAN = Endian.LITTLE


class U64BE(UnsignedIntegerField):
    SIZE = 8
    ENDIAN = Endian.BIG


class I64LE(SignedIntegerField):
    SIZE = 8
    ENDIAN = Endian.LITTLE


class I64BE(SignedIntegerField):
    SIZE = 4
    ENDIAN = Endian.BIG


class F32(SingleStructField):
    STRUCT = "f"


class F64(SingleStructField):
    STRUCT = "d"
