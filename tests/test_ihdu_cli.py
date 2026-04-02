import argparse
import unittest
from unittest import mock

from ihdu_cli import (
    build_login_params,
    command_requires_credentials,
    detect_portal_device,
    detect_portal_from_url,
    detect_user_agent,
    ensure_wifi_connected,
    encode_info,
    parse_jsonp,
)


class IhduCliTests(unittest.TestCase):
    def test_detect_portal_device_for_linux(self) -> None:
        os_name, platform_name = detect_portal_device(system_name="Linux", release_name="6.8")
        self.assertEqual(os_name, "Linux")
        self.assertEqual(platform_name, "Linux")

    def test_detect_user_agent_for_mac(self) -> None:
        user_agent = detect_user_agent(system_name="Darwin")
        self.assertIn("Macintosh", user_agent)
        self.assertIn("Chrome/146.0.0.0", user_agent)

    def test_status_does_not_require_credentials(self) -> None:
        self.assertFalse(command_requires_credentials("status"))
        self.assertTrue(command_requires_credentials("login"))
        self.assertTrue(command_requires_credentials("watch"))

    def test_parse_jsonp_extracts_payload(self) -> None:
        payload = 'jQuery1124_1({"error":"ok","online_ip":"10.252.99.173"})'
        result = parse_jsonp(payload)
        self.assertEqual(result["error"], "ok")
        self.assertEqual(result["online_ip"], "10.252.99.173")

    def test_encode_info_matches_fixture(self) -> None:
        info = {
            "username": "testuser",
            "password": "testpass",
            "ip": "10.0.0.8",
            "acid": "0",
            "enc_ver": "srun_bx1",
        }
        encoded = encode_info(info, "1234567890abcdef")
        self.assertEqual(
            encoded,
            "{SRBX1}QMHIsgOVviqSCcjBePdhIj4Dfluxd5DzKObbcrjc07TRfpbajv3xOxiuF7HGdMuKaRAZY+d+vL9MyHwWimkxMYBrgLVpC0BKbXYqLPl1u/oCboR9dfjJyZcPfBPNJtlSs76smL==",
        )

    def test_build_login_params_matches_fixture(self) -> None:
        params = build_login_params(
            username="testuser",
            password="testpass",
            ip="10.0.0.8",
            ac_id="0",
            token="1234567890abcdef",
            os_name="Linux",
            platform_name="Linux",
        )
        self.assertEqual(params["password"], "{MD5}dac198d67b2d44d2215b6c7d448637ed")
        self.assertEqual(
            params["info"],
            "{SRBX1}QMHIsgOVviqSCcjBePdhIj4Dfluxd5DzKObbcrjc07TRfpbajv3xOxiuF7HGdMuKaRAZY+d+vL9MyHwWimkxMYBrgLVpC0BKbXYqLPl1u/oCboR9dfjJyZcPfBPNJtlSs76smL==",
        )
        self.assertEqual(params["chksum"], "c671c11a36d54c02425d96f8d08d35dbcba8cbb5")

    def test_detect_portal_from_redirect_url(self) -> None:
        portal = detect_portal_from_url("http://192.168.112.30/index_32.html")
        self.assertEqual(portal, ("http://192.168.112.30", "32"))

    def test_detect_portal_from_login_hdu_url(self) -> None:
        portal = detect_portal_from_url("https://login.hdu.edu.cn/srun_portal_pc?ac_id=0&theme=pro")
        self.assertEqual(portal, ("https://login.hdu.edu.cn", "0"))

    @mock.patch("ihdu_cli.shutil.which", return_value="nmcli")
    @mock.patch("ihdu_cli.run_command")
    def test_ensure_wifi_connected_uses_nmcli_for_linux(
        self,
        run_command: mock.Mock,
        _which: mock.Mock,
    ) -> None:
        run_command.side_effect = [
            argparse.Namespace(returncode=0, stdout="", stderr=""),
            argparse.Namespace(returncode=0, stdout="", stderr=""),
        ]
        changed = ensure_wifi_connected("i-HDU", system_name="Linux")
        self.assertTrue(changed)
        self.assertEqual(run_command.call_args_list[1].args[0], ["nmcli", "device", "wifi", "connect", "i-HDU"])

    @mock.patch("ihdu_cli.run_command")
    def test_ensure_wifi_connected_skips_when_windows_already_connected(self, run_command: mock.Mock) -> None:
        run_command.return_value = argparse.Namespace(returncode=0, stdout="SSID                   : i-HDU\n", stderr="")
        changed = ensure_wifi_connected("i-HDU", system_name="Windows")
        self.assertFalse(changed)
        self.assertEqual(len(run_command.call_args_list), 1)


if __name__ == "__main__":
    unittest.main()
