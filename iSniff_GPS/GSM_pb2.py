# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: GSM.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='GSM.proto',
  package='',
  serialized_pb=_b('\n\tGSM.proto\"<\n\x06MyCell\x12\x0b\n\x03MCC\x18\x01 \x01(\x03\x12\x0b\n\x03MNC\x18\x02 \x01(\x03\x12\x0b\n\x03\x43ID\x18\x03 \x01(\x03\x12\x0b\n\x03LAC\x18\x04 \x01(\x03\"T\n\x0f\x43\x65llReqToApple1\x12\x15\n\x04\x63\x65ll\x18\x01 \x03(\x0b\x32\x07.MyCell\x12\x0e\n\x06param3\x18\x03 \x01(\x03\x12\x0e\n\x06param4\x18\x04 \x01(\x03\x12\n\n\x02ua\x18\x05 \x01(\t\"M\n\x10\x43\x65llReqToApple25\x12\x15\n\x04\x63\x65ll\x18\x19 \x02(\x0b\x32\x07.MyCell\x12\x10\n\x08unknown3\x18\x03 \x01(\x03\x12\x10\n\x08unknown4\x18\x04 \x01(\x03\"\xee\x01\n\rCellResponse1\x12\x0b\n\x03MCC\x18\x01 \x01(\x03\x12\x0b\n\x03MNC\x18\x02 \x01(\x03\x12\x0b\n\x03\x43ID\x18\x03 \x01(\x03\x12\x0b\n\x03LAC\x18\x04 \x01(\x03\x12)\n\x08location\x18\x05 \x01(\x0b\x32\x17.CellResponse1.Location\x12\x0f\n\x07\x63hannel\x18\x0b \x01(\x03\x12\x0e\n\x06\x64\x61ta12\x18\x0c \x01(\x03\x1a]\n\x08Location\x12\x10\n\x08latitude\x18\x01 \x02(\x03\x12\x11\n\tlongitude\x18\x02 \x02(\x03\x12\r\n\x05\x64\x61ta3\x18\x03 \x01(\x03\x12\r\n\x05\x64\x61ta4\x18\x04 \x01(\x03\x12\x0e\n\x06\x64\x61ta12\x18\x0c \x01(\x03\"\xe5\x01\n\x0e\x43\x65llResponse22\x12\x0b\n\x03MCC\x18\x01 \x01(\x03\x12\x0b\n\x03MNC\x18\x02 \x01(\x03\x12\x0b\n\x03\x43ID\x18\x03 \x01(\x03\x12\x0b\n\x03LAC\x18\x04 \x01(\x03\x12*\n\x08location\x18\x05 \x01(\x0b\x32\x18.CellResponse22.Location\x12\x0f\n\x07\x63hannel\x18\x06 \x01(\x03\x1a\x62\n\x08Location\x12\x10\n\x08latitude\x18\x01 \x02(\x03\x12\x11\n\tlongitude\x18\x02 \x02(\x03\x12\x12\n\nconfidence\x18\x03 \x01(\x03\x12\r\n\x05\x64\x61ta4\x18\x04 \x01(\x03\x12\x0e\n\x06\x64\x61ta12\x18\x0c \x01(\x03\"4\n\x13\x43\x65llInfoFromApple22\x12\x1d\n\x04\x63\x65ll\x18\x16 \x03(\x0b\x32\x0f.CellResponse22\"2\n\x12\x43\x65llInfoFromApple1\x12\x1c\n\x04\x63\x65ll\x18\x01 \x03(\x0b\x32\x0e.CellResponse1')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)




_MYCELL = _descriptor.Descriptor(
  name='MyCell',
  full_name='MyCell',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='MCC', full_name='MyCell.MCC', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='MNC', full_name='MyCell.MNC', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='CID', full_name='MyCell.CID', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='LAC', full_name='MyCell.LAC', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=13,
  serialized_end=73,
)


_CELLREQTOAPPLE1 = _descriptor.Descriptor(
  name='CellReqToApple1',
  full_name='CellReqToApple1',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='cell', full_name='CellReqToApple1.cell', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='param3', full_name='CellReqToApple1.param3', index=1,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='param4', full_name='CellReqToApple1.param4', index=2,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='ua', full_name='CellReqToApple1.ua', index=3,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=75,
  serialized_end=159,
)


_CELLREQTOAPPLE25 = _descriptor.Descriptor(
  name='CellReqToApple25',
  full_name='CellReqToApple25',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='cell', full_name='CellReqToApple25.cell', index=0,
      number=25, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='unknown3', full_name='CellReqToApple25.unknown3', index=1,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='unknown4', full_name='CellReqToApple25.unknown4', index=2,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=161,
  serialized_end=238,
)


_CELLRESPONSE1_LOCATION = _descriptor.Descriptor(
  name='Location',
  full_name='CellResponse1.Location',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='latitude', full_name='CellResponse1.Location.latitude', index=0,
      number=1, type=3, cpp_type=2, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='longitude', full_name='CellResponse1.Location.longitude', index=1,
      number=2, type=3, cpp_type=2, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data3', full_name='CellResponse1.Location.data3', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data4', full_name='CellResponse1.Location.data4', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data12', full_name='CellResponse1.Location.data12', index=4,
      number=12, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=386,
  serialized_end=479,
)

_CELLRESPONSE1 = _descriptor.Descriptor(
  name='CellResponse1',
  full_name='CellResponse1',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='MCC', full_name='CellResponse1.MCC', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='MNC', full_name='CellResponse1.MNC', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='CID', full_name='CellResponse1.CID', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='LAC', full_name='CellResponse1.LAC', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='location', full_name='CellResponse1.location', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='channel', full_name='CellResponse1.channel', index=5,
      number=11, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data12', full_name='CellResponse1.data12', index=6,
      number=12, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_CELLRESPONSE1_LOCATION, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=241,
  serialized_end=479,
)


_CELLRESPONSE22_LOCATION = _descriptor.Descriptor(
  name='Location',
  full_name='CellResponse22.Location',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='latitude', full_name='CellResponse22.Location.latitude', index=0,
      number=1, type=3, cpp_type=2, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='longitude', full_name='CellResponse22.Location.longitude', index=1,
      number=2, type=3, cpp_type=2, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='confidence', full_name='CellResponse22.Location.confidence', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data4', full_name='CellResponse22.Location.data4', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data12', full_name='CellResponse22.Location.data12', index=4,
      number=12, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=613,
  serialized_end=711,
)

_CELLRESPONSE22 = _descriptor.Descriptor(
  name='CellResponse22',
  full_name='CellResponse22',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='MCC', full_name='CellResponse22.MCC', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='MNC', full_name='CellResponse22.MNC', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='CID', full_name='CellResponse22.CID', index=2,
      number=3, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='LAC', full_name='CellResponse22.LAC', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='location', full_name='CellResponse22.location', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='channel', full_name='CellResponse22.channel', index=5,
      number=6, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[_CELLRESPONSE22_LOCATION, ],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=482,
  serialized_end=711,
)


_CELLINFOFROMAPPLE22 = _descriptor.Descriptor(
  name='CellInfoFromApple22',
  full_name='CellInfoFromApple22',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='cell', full_name='CellInfoFromApple22.cell', index=0,
      number=22, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=713,
  serialized_end=765,
)


_CELLINFOFROMAPPLE1 = _descriptor.Descriptor(
  name='CellInfoFromApple1',
  full_name='CellInfoFromApple1',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='cell', full_name='CellInfoFromApple1.cell', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=767,
  serialized_end=817,
)

_CELLREQTOAPPLE1.fields_by_name['cell'].message_type = _MYCELL
_CELLREQTOAPPLE25.fields_by_name['cell'].message_type = _MYCELL
_CELLRESPONSE1_LOCATION.containing_type = _CELLRESPONSE1
_CELLRESPONSE1.fields_by_name['location'].message_type = _CELLRESPONSE1_LOCATION
_CELLRESPONSE22_LOCATION.containing_type = _CELLRESPONSE22
_CELLRESPONSE22.fields_by_name['location'].message_type = _CELLRESPONSE22_LOCATION
_CELLINFOFROMAPPLE22.fields_by_name['cell'].message_type = _CELLRESPONSE22
_CELLINFOFROMAPPLE1.fields_by_name['cell'].message_type = _CELLRESPONSE1
DESCRIPTOR.message_types_by_name['MyCell'] = _MYCELL
DESCRIPTOR.message_types_by_name['CellReqToApple1'] = _CELLREQTOAPPLE1
DESCRIPTOR.message_types_by_name['CellReqToApple25'] = _CELLREQTOAPPLE25
DESCRIPTOR.message_types_by_name['CellResponse1'] = _CELLRESPONSE1
DESCRIPTOR.message_types_by_name['CellResponse22'] = _CELLRESPONSE22
DESCRIPTOR.message_types_by_name['CellInfoFromApple22'] = _CELLINFOFROMAPPLE22
DESCRIPTOR.message_types_by_name['CellInfoFromApple1'] = _CELLINFOFROMAPPLE1

MyCell = _reflection.GeneratedProtocolMessageType('MyCell', (_message.Message,), dict(
  DESCRIPTOR = _MYCELL,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:MyCell)
  ))
_sym_db.RegisterMessage(MyCell)

CellReqToApple1 = _reflection.GeneratedProtocolMessageType('CellReqToApple1', (_message.Message,), dict(
  DESCRIPTOR = _CELLREQTOAPPLE1,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellReqToApple1)
  ))
_sym_db.RegisterMessage(CellReqToApple1)

CellReqToApple25 = _reflection.GeneratedProtocolMessageType('CellReqToApple25', (_message.Message,), dict(
  DESCRIPTOR = _CELLREQTOAPPLE25,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellReqToApple25)
  ))
_sym_db.RegisterMessage(CellReqToApple25)

CellResponse1 = _reflection.GeneratedProtocolMessageType('CellResponse1', (_message.Message,), dict(

  Location = _reflection.GeneratedProtocolMessageType('Location', (_message.Message,), dict(
    DESCRIPTOR = _CELLRESPONSE1_LOCATION,
    __module__ = 'GSM_pb2'
    # @@protoc_insertion_point(class_scope:CellResponse1.Location)
    ))
  ,
  DESCRIPTOR = _CELLRESPONSE1,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellResponse1)
  ))
_sym_db.RegisterMessage(CellResponse1)
_sym_db.RegisterMessage(CellResponse1.Location)

CellResponse22 = _reflection.GeneratedProtocolMessageType('CellResponse22', (_message.Message,), dict(

  Location = _reflection.GeneratedProtocolMessageType('Location', (_message.Message,), dict(
    DESCRIPTOR = _CELLRESPONSE22_LOCATION,
    __module__ = 'GSM_pb2'
    # @@protoc_insertion_point(class_scope:CellResponse22.Location)
    ))
  ,
  DESCRIPTOR = _CELLRESPONSE22,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellResponse22)
  ))
_sym_db.RegisterMessage(CellResponse22)
_sym_db.RegisterMessage(CellResponse22.Location)

CellInfoFromApple22 = _reflection.GeneratedProtocolMessageType('CellInfoFromApple22', (_message.Message,), dict(
  DESCRIPTOR = _CELLINFOFROMAPPLE22,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellInfoFromApple22)
  ))
_sym_db.RegisterMessage(CellInfoFromApple22)

CellInfoFromApple1 = _reflection.GeneratedProtocolMessageType('CellInfoFromApple1', (_message.Message,), dict(
  DESCRIPTOR = _CELLINFOFROMAPPLE1,
  __module__ = 'GSM_pb2'
  # @@protoc_insertion_point(class_scope:CellInfoFromApple1)
  ))
_sym_db.RegisterMessage(CellInfoFromApple1)


# @@protoc_insertion_point(module_scope)
