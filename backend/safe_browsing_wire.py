"""Minimal v5 SearchUrlsResponse schema, decoded by Google's Protobuf runtime.

Wire fields follow the URL-search response contract (threats=1, cache_duration=2;
ThreatUrl: url=1, threat_types=2). Live synthetic response fixtures verify these.
https://developers.google.com/safe-browsing/reference/rpc/google.security.safebrowsing.v5
"""
from google.protobuf import descriptor_pb2, descriptor_pool, duration_pb2, message_factory

schema = descriptor_pb2.FileDescriptorProto(name='mailguard_url_search.proto', package='mailguard', syntax='proto3')
schema.dependency.append('google/protobuf/duration.proto')
threat = schema.message_type.add(name='ThreatUrl')
threat.field.add(name='url', number=1, type=9, label=1)  # string
threat.field.add(name='threat_types', number=2, type=5, label=3)  # repeated enum numbers
response = schema.message_type.add(name='SearchUrlsResponse')
response.field.add(name='threats', number=1, type=11, type_name='.mailguard.ThreatUrl', label=3)
response.field.add(name='cache_duration', number=2, type=11, type_name='.google.protobuf.Duration', label=1)
pool = descriptor_pool.DescriptorPool()
pool.AddSerializedFile(duration_pb2.DESCRIPTOR.serialized_pb)
pool.Add(schema)
SearchUrlsResponse = message_factory.GetMessageClass(pool.FindMessageTypeByName('mailguard.SearchUrlsResponse'))


def decode_response(content: bytes) -> dict:
    response = SearchUrlsResponse.FromString(content)
    if not response.HasField('cache_duration'):
        raise ValueError('Missing cache duration')
    if response.cache_duration.seconds < 0 or not 0 <= response.cache_duration.nanos < 1_000_000_000:
        raise ValueError('Invalid cache duration')
    names = {1:'MALWARE', 2:'SOCIAL_ENGINEERING', 3:'UNWANTED_SOFTWARE', 4:'POTENTIALLY_HARMFUL_APPLICATION'}
    threats = []
    for threat in response.threats:
        if not threat.url or not threat.threat_types or any(t not in names for t in threat.threat_types):
            raise ValueError('Unrecognized threat data')
        threats.append({'threatTypes':[names[t] for t in threat.threat_types]})
    return {'threats': threats, 'cacheDuration':response.cache_duration.ToJsonString()}
