import os

import pytest

os.environ.setdefault("TEST_MODE", "true")
os.environ.setdefault("HIBP_API_KEY", "test")
os.environ.setdefault("APIFY_API_TOKEN", "test")
os.environ.setdefault("APIFY_ACTOR_ID", "test")
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("SPIDERFOOT_HOST", "http://localhost:5001")

import tools.ai_audit as ai_audit_tool
import tools.blackbird as blackbird_tool
import tools.broker_scan as broker_scan_tool
import tools.ghunt as ghunt_tool
import tools.hibp as hibp_tool
import tools.holehe as holehe_tool
import tools.maigret as maigret_tool
import tools.spiderfoot as spiderfoot_tool
from models.ai_audit import AiAuditInput, AiAuditOutput
from models.blackbird import BlackbirdInput, BlackbirdOutput
from models.broker_scan import BrokerScanInput, BrokerScanOutput
from models.ghunt import GHuntInput, GHuntOutput
from models.hibp import HibpInput, HibpOutput
from models.holehe import HoleheInput, HoleheOutput
from models.maigret import MaigretInput, MaigretOutput
from models.shared import ToolResult
from models.spiderfoot import SpiderfootInput, SpiderfootOutput


class TestHibpTool:
    def test_returns_tool_result(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        assert result.success is True

    def test_tool_name(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        assert result.tool == "hibp"

    def test_data_validates_as_hibp_output(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        output = HibpOutput(**result.data)
        assert output.breach_count == 3
        assert len(output.breaches) == 3

    def test_breach_records_have_expected_fields(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        output = HibpOutput(**result.data)
        breach = output.breaches[0]
        assert breach.name == "Adobe"
        assert breach.domain == "adobe.com"
        assert isinstance(breach.data_classes, list)

    def test_error_is_none_on_success(self):
        inp = HibpInput(input_type="email", value="test@example.com")
        result = hibp_tool.run(inp)
        assert result.error is None


class TestSpiderfootTool:
    def test_returns_tool_result(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = spiderfoot_tool.run(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = spiderfoot_tool.run(inp)
        assert result.success is True

    def test_data_validates_as_spiderfoot_output(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = spiderfoot_tool.run(inp)
        output = SpiderfootOutput(**result.data)
        assert output.status == "FINISHED"
        assert output.element_count == 5
        assert len(output.elements) == 5

    def test_elements_have_expected_fields(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        result = spiderfoot_tool.run(inp)
        output = SpiderfootOutput(**result.data)
        el = output.elements[0]
        assert el.module == "sfp_gravatar"
        assert isinstance(el.confidence, int)

    def test_default_modules_list(self):
        inp = SpiderfootInput(target="test@example.com", target_type="emailaddr")
        assert "sfp_hibp" in inp.modules
        assert "sfp_emailrep" in inp.modules
        # sfp_social removed — causes consistent timeouts; coverage via Holehe/Blackbird
        assert len(inp.modules) == 5


class TestBrokerScanTool:
    def test_returns_tool_result(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        assert result.success is True

    def test_data_validates_as_broker_output(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        output = BrokerScanOutput(**result.data)
        assert output.brokers_found_count == 4
        assert output.exposure_score == 62

    def test_easyoptouts_url_present(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        output = BrokerScanOutput(**result.data)
        assert output.easyoptouts_url == "https://easyoptouts.com/dashboard"

    def test_broker_profiles_have_optout_urls(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        output = BrokerScanOutput(**result.data)
        for profile in output.brokers_found:
            assert profile.optout_url != ""

    def test_priority_optouts_populated(self):
        inp = BrokerScanInput(input_type="name", value="John Doe")
        result = broker_scan_tool.run(inp)
        output = BrokerScanOutput(**result.data)
        assert len(output.priority_optouts) > 0


class TestAiAuditTool:
    def test_returns_tool_result(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = ai_audit_tool.run(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt"])
        result = ai_audit_tool.run(inp)
        assert result.success is True

    def test_data_validates_as_ai_audit_output(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = ai_audit_tool.run(inp)
        output = AiAuditOutput(**result.data)
        assert output.high_risk_count == 2
        assert output.overall_risk == "high"

    def test_platforms_found_count(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = ai_audit_tool.run(inp)
        output = AiAuditOutput(**result.data)
        assert len(output.platforms_found) == 4

    def test_action_items_populated(self):
        inp = AiAuditInput(platforms=["claude", "chatgpt", "gemini", "grok"])
        result = ai_audit_tool.run(inp)
        output = AiAuditOutput(**result.data)
        assert len(output.action_items) > 0


class TestHoleheTool:
    def test_returns_tool_result(self):
        inp = HoleheInput(email="test@example.com")
        result = holehe_tool.run(inp)
        assert isinstance(result, ToolResult)

    def test_success_true_in_test_mode(self):
        inp = HoleheInput(email="test@example.com")
        result = holehe_tool.run(inp)
        assert result.success is True

    def test_data_validates_as_holehe_output(self):
        inp = HoleheInput(email="test@example.com")
        result = holehe_tool.run(inp)
        output = HoleheOutput(**result.data)
        assert output.platforms_checked > 0
        assert output.found_count == len(output.platforms_found)

    def test_found_platforms_have_expected_fields(self):
        inp = HoleheInput(email="test@example.com")
        result = holehe_tool.run(inp)
        output = HoleheOutput(**result.data)
        for match in output.platforms_found:
            assert match.platform
            assert match.exists is True


class TestBlackbirdTool:
    def test_returns_tool_result(self):
        result = blackbird_tool.run(BlackbirdInput(email="test@example.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = blackbird_tool.run(BlackbirdInput(email="test@example.com"))
        assert result.success is True

    def test_data_validates_as_blackbird_output(self):
        result = blackbird_tool.run(BlackbirdInput(email="test@example.com"))
        output = BlackbirdOutput(**result.data)
        assert output.found_count == len(output.accounts_found)

    def test_accounts_have_platform_and_url(self):
        result = blackbird_tool.run(BlackbirdInput(email="test@example.com"))
        output = BlackbirdOutput(**result.data)
        for account in output.accounts_found:
            assert account.platform
            assert account.url.startswith("http")


class TestMaigretTool:
    def test_returns_tool_result(self):
        result = maigret_tool.run(MaigretInput(username="testuser"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = maigret_tool.run(MaigretInput(username="testuser"))
        assert result.success is True

    def test_data_validates_as_maigret_output(self):
        result = maigret_tool.run(MaigretInput(username="testuser"))
        output = MaigretOutput(**result.data)
        assert output.found_count == len(output.profiles_found)

    def test_profiles_have_url(self):
        result = maigret_tool.run(MaigretInput(username="testuser"))
        output = MaigretOutput(**result.data)
        for profile in output.profiles_found:
            assert profile.url.startswith("http")


class TestGHuntTool:
    def test_returns_tool_result(self):
        result = ghunt_tool.run(GHuntInput(email="test@gmail.com"))
        assert isinstance(result, ToolResult)

    def test_success_in_test_mode(self):
        result = ghunt_tool.run(GHuntInput(email="test@gmail.com"))
        assert result.success is True

    def test_data_validates_as_ghunt_output(self):
        result = ghunt_tool.run(GHuntInput(email="test@gmail.com"))
        output = GHuntOutput(**result.data)
        assert isinstance(output.found, bool)

    def test_found_has_services(self):
        result = ghunt_tool.run(GHuntInput(email="test@gmail.com"))
        output = GHuntOutput(**result.data)
        if output.found:
            assert isinstance(output.google_services, list)


class TestToolResultEnvelope:
    def test_error_result_shape(self):
        import json
        from pathlib import Path

        raw = json.loads(
            (Path(__file__).parent / "fixtures" / "error_response.json").read_text()
        )
        result = ToolResult(**raw)
        assert result.success is False
        assert result.error is not None
        assert result.data == {}
