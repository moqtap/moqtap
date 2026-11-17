//! Each `RangeFilterError` names itself with a stable code.

use moqtap_codec::range_filter::RangeFilterError;

#[test]
fn every_range_filter_error_has_its_code() {
    let cases = [
        (RangeFilterError::NotARangeFilter(0x24), "not_a_range_filter"),
        (RangeFilterError::Malformed { detail: "short" }, "malformed"),
        (RangeFilterError::DeltaOverflow { base: u64::MAX, delta: 1 }, "delta_overflow"),
        (RangeFilterError::PriorityAboveTheField(300), "priority_above_the_field"),
        (RangeFilterError::PropertyTypeIsNotAnInteger(1), "property_type_is_not_an_integer"),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code, "{error:?}");
    }
}
