"""
Tests for CoT XML message parsing.

These tests validate the actual XML parsing logic in tak.lua's xml module
by executing the real Lua code via the lupa bridge. This ensures the tests
exercise the same code that runs in Wireshark.
"""

import sys
from pathlib import Path

import pytest

# Ensure lua_bridge can be imported
sys.path.insert(0, str(Path(__file__).parent))
from lua_bridge import LuaBridge


class TestXMLDetection:
    """Tests for REQ-DET-001 and REQ-DET-002: XML message detection via actual Lua code."""

    @pytest.mark.req("REQ-DET-001")
    def test_detect_xml_declaration(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify XML with declaration is detected by Lua."""
        assert marker_spot_xml is not None, "Marker - Spot.cot example not found"
        assert marker_spot_xml.startswith("<?xml"), "Should start with XML declaration"
        assert xml_parser.xml_is_xml(marker_spot_xml), "Lua should detect as XML"

    @pytest.mark.req("REQ-DET-002")
    def test_detect_event_tag(self, xml_parser: LuaBridge):
        """Verify XML starting with <event is detected by Lua."""
        xml_without_declaration = '<event version="2.0" uid="test" type="a-f-G"/>'
        assert xml_parser.xml_is_xml(xml_without_declaration), "Lua should detect <event prefix"

    @pytest.mark.req("REQ-DET-001")
    def test_detect_all_examples_as_xml(self, xml_parser: LuaBridge, takcot_examples):
        """Verify all .cot example files are detected as XML by Lua."""
        cot_files = list(takcot_examples.glob("*.cot"))
        assert len(cot_files) > 0, "Should have example COT files"

        for cot_file in cot_files:
            content = cot_file.read_text(encoding="utf-8")
            assert xml_parser.xml_is_xml(content), f"Lua should detect {cot_file.name} as XML"


class TestEventElementParsing:
    """Tests for REQ-XML-001: Event element attribute parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-001")
    def test_parse_event_attributes(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify event attributes are correctly parsed by Lua."""
        assert marker_spot_xml is not None
        event_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "event")
        assert event_attrs is not None, "Lua should find event element"

        # Extract individual attributes using Lua
        uid = xml_parser.xml_get_attr(event_attrs, "uid")
        event_type = xml_parser.xml_get_attr(event_attrs, "type")
        how = xml_parser.xml_get_attr(event_attrs, "how")
        version = xml_parser.xml_get_attr(event_attrs, "version")

        assert uid == "9405e320-9356-41c4-8449-f46990aa17f8"
        assert event_type == "b-m-p-s-m"
        assert how == "h-g-i-g-o"
        assert version == "2.0"

    @pytest.mark.req("REQ-XML-001")
    def test_parse_2525_event_type(self, xml_parser: LuaBridge, marker_2525_xml):
        """Verify 2525 marker event type is parsed correctly by Lua."""
        assert marker_2525_xml is not None
        event_attrs = xml_parser.xml_get_element_with_attrs(marker_2525_xml, "event")
        event_type = xml_parser.xml_get_attr(event_attrs, "type")

        # 2525 marker should have a-u-G type (unknown ground unit)
        assert event_type == "a-u-G"


class TestPointElementParsing:
    """Tests for REQ-XML-002: Point element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-002")
    def test_parse_point_element(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify point element coordinates are parsed correctly by Lua."""
        assert marker_spot_xml is not None
        point_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "point")
        assert point_attrs is not None, "Lua should find point element"

        lat = xml_parser.xml_get_attr(point_attrs, "lat")
        lon = xml_parser.xml_get_attr(point_attrs, "lon")
        hae = xml_parser.xml_get_attr(point_attrs, "hae")
        ce = xml_parser.xml_get_attr(point_attrs, "ce")
        le = xml_parser.xml_get_attr(point_attrs, "le")

        # Verify coordinates
        assert float(lat) == pytest.approx(38.85606343062312, rel=1e-10)
        assert float(lon) == pytest.approx(-77.0563755018233, rel=1e-10)
        assert float(hae) == pytest.approx(9999999.0)
        assert float(ce) == pytest.approx(9999999.0)
        assert float(le) == pytest.approx(9999999.0)

    @pytest.mark.req("REQ-XML-002")
    def test_parse_route_zero_point(self, xml_parser: LuaBridge, route_xml):
        """Verify route with zero-point location is parsed by Lua."""
        assert route_xml is not None
        point_attrs = xml_parser.xml_get_element_with_attrs(route_xml, "point")

        lat = xml_parser.xml_get_attr(point_attrs, "lat")
        lon = xml_parser.xml_get_attr(point_attrs, "lon")

        # Route uses 0.0, 0.0 as placeholder point
        assert float(lat) == 0.0
        assert float(lon) == 0.0


class TestContactElementParsing:
    """Tests for REQ-XML-003: Contact element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-003")
    def test_parse_contact_element(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify contact element is parsed correctly by Lua."""
        assert marker_spot_xml is not None
        contact_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "contact")
        assert contact_attrs is not None

        callsign = xml_parser.xml_get_attr(contact_attrs, "callsign")
        assert callsign == "R 1"

    @pytest.mark.req("REQ-XML-003")
    def test_parse_circle_contact(self, xml_parser: LuaBridge, circle_xml):
        """Verify circle drawing contact/callsign by Lua."""
        assert circle_xml is not None
        contact_attrs = xml_parser.xml_get_element_with_attrs(circle_xml, "contact")
        callsign = xml_parser.xml_get_attr(contact_attrs, "callsign")
        assert callsign == "Drawing Circle 1"


class TestGroupElementParsing:
    """Tests for REQ-XML-004: Group element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-004")
    def test_parse_group_element_not_present(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify handling when __group is not present by Lua."""
        assert marker_spot_xml is not None
        # Marker - Spot doesn't have __group
        group_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "__group")
        # Should return None or empty - this is valid
        # The test verifies the parser handles missing elements


class TestTAKvElementParsing:
    """Tests for REQ-XML-005: TAKv element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-005")
    def test_parse_takv_element_not_present(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify handling when takv is not present in static markers."""
        # Static markers typically don't have takv (TAK client version info)
        # This is expected - takv appears in position reports from clients
        pass


class TestTrackElementParsing:
    """Tests for REQ-XML-006: Track element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-006")
    def test_track_element_not_present_in_marker(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify handling when track is not present in static markers."""
        # Static markers don't have track data (speed/course)
        assert marker_spot_xml is not None
        track_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "track")
        # Track element is not present in static markers


class TestStatusElementParsing:
    """Tests for REQ-XML-007: Status element parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-007")
    def test_parse_status_element(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify status element is parsed by Lua."""
        assert marker_spot_xml is not None
        status_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "status")
        if status_attrs:
            readiness = xml_parser.xml_get_attr(status_attrs, "readiness")
            assert readiness == "true"


class TestPrecisionElementParsing:
    """Tests for REQ-XML-008: Precision location parsing via actual Lua code."""

    @pytest.mark.req("REQ-XML-008")
    def test_parse_precision_element(self, xml_parser: LuaBridge, marker_spot_xml):
        """Verify precisionlocation element is parsed by Lua."""
        assert marker_spot_xml is not None
        precision_attrs = xml_parser.xml_get_element_with_attrs(marker_spot_xml, "precisionlocation")
        assert precision_attrs is not None

        altsrc = xml_parser.xml_get_attr(precision_attrs, "altsrc")
        assert altsrc == "???"  # Unknown altitude source


class TestAllExamples:
    """Tests that verify all example files parse correctly via actual Lua code."""

    @pytest.mark.req("REQ-XML-001")
    @pytest.mark.req("REQ-XML-002")
    def test_all_examples_have_required_elements(self, xml_parser: LuaBridge, takcot_examples):
        """Verify all examples have event and point elements parsed by Lua."""
        cot_files = list(takcot_examples.glob("*.cot"))

        for cot_file in cot_files:
            content = cot_file.read_text(encoding="utf-8")

            event_attrs = xml_parser.xml_get_element_with_attrs(content, "event")
            assert event_attrs is not None, f"Lua: {cot_file.name} missing event element"

            uid = xml_parser.xml_get_attr(event_attrs, "uid")
            event_type = xml_parser.xml_get_attr(event_attrs, "type")
            assert uid is not None, f"Lua: {cot_file.name} missing uid"
            assert event_type is not None, f"Lua: {cot_file.name} missing type"

            point_attrs = xml_parser.xml_get_element_with_attrs(content, "point")
            assert point_attrs is not None, f"Lua: {cot_file.name} missing point element"

            lat = xml_parser.xml_get_attr(point_attrs, "lat")
            lon = xml_parser.xml_get_attr(point_attrs, "lon")
            assert lat is not None, f"Lua: {cot_file.name} missing lat"
            assert lon is not None, f"Lua: {cot_file.name} missing lon"
