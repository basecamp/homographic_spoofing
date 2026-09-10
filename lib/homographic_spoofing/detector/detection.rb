# `span` is the [offset, length] of the address component the detection came
# from, in characters, within the field — so the sanitizer punycodes the
# offending label only inside that component and never rewrites a matching label
# in a sibling component (a local part equal to a spoofed domain label, say). It
# is derived from the parsed address, not by re-scanning the raw string for an
# "@", which trailing CFWS comments or a display name can carry spuriously. It
# is nil for detectors that run against a standalone string (a bare IDN or
# quoted string), where the whole field is the one component.
class HomographicSpoofing::Detector::Detection < Struct.new(:reason, :label, :span)
end
