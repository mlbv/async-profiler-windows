# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Decode the OTLP Profiles wire data independently of the Java exporter."""
from pathlib import Path


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise AssertionError('Invalid protobuf varint')


def fields(data):
    result = {}
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        assert key >> 3 > 0
        wire = key & 7
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 2, 5):
            if wire == 2:
                size, offset = varint(data, offset)
            else:
                size = 8 if wire == 1 else 4
            value = data[offset:offset + size]
            assert len(value) == size
            offset += size
        else:
            raise AssertionError(f'Unsupported protobuf wire type {wire}')
        result.setdefault(key >> 3, []).append(value)
    return result


def validate(path, required_frame, expected_events=None, *, aggregated=False, expected_values=None, expected_type=None, expected_unit=None):
    root = fields(Path(path).read_bytes())
    dictionary = fields(root[2][0])
    strings = [value.decode('utf-8') for value in dictionary[5]]
    functions = [strings[fields(value).get(1, [0])[0]] for value in dictionary[3]]
    assert any(required_frame in value for value in functions), functions
    locations = [fields(value) for value in dictionary[2]]
    for location in locations:
        for line in location.get(3, []):
            assert fields(line).get(1, [0])[0] < len(functions)
    stacks = [fields(value) for value in dictionary[7]]
    for stack in stacks:
        for packed in stack.get(1, []):
            offset = 0
            while offset < len(packed):
                index, offset = varint(packed, offset)
                assert index < len(locations)
    count = 0
    value_sum = 0
    for resource in root[1]:
        for scope in fields(resource)[2]:
            for raw_profile in fields(scope)[2]:
                profile = fields(raw_profile)
                assert len(profile[3][0]) == 8 and profile[6][0] > 0
                if expected_type is not None or expected_unit is not None:
                    value_type = fields(profile[1][0])
                    if expected_type is not None:
                        assert strings[value_type.get(1, [0])[0]] == expected_type
                    if expected_unit is not None:
                        assert strings[value_type.get(2, [0])[0]] == expected_unit
                for sample in profile.get(2, []):
                    parsed = fields(sample)
                    assert parsed[1][0] < len(stacks)
                    if aggregated:
                        values = parsed[4]
                        assert all(isinstance(value, int) and value > 0 for value in values), values
                        count += sum(values)
                    else:
                        timestamps = parsed[5][0]
                        assert len(timestamps) % 8 == 0
                        count += len(timestamps) // 8
                    if expected_values is not None:
                        values = parsed.get(4)
                        if values is None:
                            value_sum += len(parsed[5][0]) // 8
                        else:
                            for value in values:
                                if isinstance(value, int):
                                    value_sum += value
                                else:
                                    offset = 0
                                    while offset < len(value):
                                        decoded, offset = varint(value, offset)
                                        value_sum += decoded
    assert count > 0
    if expected_events is not None:
        assert count == expected_events, (count, expected_events)
    if expected_values is not None:
        assert value_sum == expected_values, (value_sum, expected_values)
    return count
