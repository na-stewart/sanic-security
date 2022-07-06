import os
import pytest

from sanic import Sanic

from sanic_security.configuration import Config

"""
An effective, simple, and async security library for the Sanic framework.
Copyright (C) 2020-present Aidan Stewart

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""


@pytest.mark.usefixtures("app")
class TestConfiguration:
    """
    Tests configuration.
    """

    def test_environment_variable_load(self, app: Sanic):
        """
        Config loads environment variables.
        """
        os.environ["SANIC_SECURITY_SECRET"] = "test-secret"
        security_config = Config()
        security_config.load_environment_variables()
        assert security_config.SANIC_SECURITY_SECRET == "test-secret"

        assert 'SECRET' not in app.config
        app.config.update_config(security_config)
        assert app.config.SANIC_SECURITY_SECRET == 'test-secret'
