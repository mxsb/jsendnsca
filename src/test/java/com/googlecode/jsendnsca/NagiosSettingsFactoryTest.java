/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.googlecode.jsendnsca;

import org.apache.commons.lang.StringUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.util.Properties;

import static org.junit.Assert.assertEquals;

public class NagiosSettingsFactoryTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldCreateDefaultNagiosSettingForEmptyProperties() throws Exception {
        final Properties emptyProperties = new Properties();

        final NagiosSettings settings = NagiosSettingsFactory.createSettings(emptyProperties);

        assertEquals("localhost", settings.getNagiosHost());
        assertEquals(5667, settings.getPort());
        assertEquals("", settings.getPassword());
        assertEquals(5000, settings.getConnectTimeout());
        assertEquals(10000, settings.getTimeout());
        assertEquals("NullEncryptor", settings.getEncryptor().getClass().getSimpleName());
        assertEquals(512, settings.getMaxMessageSizeInChars());
    }

    @Test
    public void shouldOverideDefaultSettingsWithValidProperties() throws Exception {
        final Properties overrideAllSettings = new Properties();
        overrideAllSettings.setProperty("nagios.nsca.host", "foobar");
        overrideAllSettings.setProperty("nagios.nsca.port", "7665");
        overrideAllSettings.setProperty("nagios.nsca.password", "secret");
        overrideAllSettings.setProperty("nagios.nsca.timeout", "20000");
        overrideAllSettings.setProperty("nagios.nsca.connect.timeout", "10000");
        overrideAllSettings.setProperty("nagios.nsca.encryption", "xor");

        final NagiosSettings settings = NagiosSettingsFactory.createSettings(overrideAllSettings);

        assertEquals("foobar", settings.getNagiosHost());
        assertEquals(7665, settings.getPort());
        assertEquals("secret", settings.getPassword());
        assertEquals(10000, settings.getConnectTimeout());
        assertEquals(20000, settings.getTimeout());
        assertEquals("XorEncryptor", settings.getEncryptor().getClass().getSimpleName());
        assertEquals(512, settings.getMaxMessageSizeInChars());
    }

    @Test
    public void shouldOverideDefaultSettingsWithValidPropertiesFile() throws Exception {
        final NagiosSettings settings = NagiosSettingsFactory.createSettings(new File("src/test/resources/nsca.properties"));

        assertEquals("foobar", settings.getNagiosHost());
        assertEquals(7665, settings.getPort());
        assertEquals("password", settings.getPassword());
        assertEquals(10000, settings.getConnectTimeout());
        assertEquals(20000, settings.getTimeout());
        assertEquals("XorEncryptor", settings.getEncryptor().getClass().getSimpleName());
        assertEquals(512, settings.getMaxMessageSizeInChars());
    }

    @Test
    public void shouldOverideHostOnly() throws Exception {
        final Properties overrideHostNameOnly = new Properties();
        overrideHostNameOnly.setProperty("nagios.nsca.host", "foobar");

        final NagiosSettings settings = NagiosSettingsFactory.createSettings(overrideHostNameOnly);

        assertEquals("foobar", settings.getNagiosHost());
        assertEquals(5667, settings.getPort());
        assertEquals("", settings.getPassword());
        assertEquals(5000, settings.getConnectTimeout());
        assertEquals(10000, settings.getTimeout());
        assertEquals("NullEncryptor", settings.getEncryptor().getClass().getSimpleName());
        assertEquals(512, settings.getMaxMessageSizeInChars());
    }

    @Test
    public void shouldThrowNagiosConfigurationExceptionForEmptyPropertyValue() throws Exception {
        expectedException.expect(NagiosConfigurationException.class);
        expectedException.expectMessage("Key [nagios.nsca.host] value cannot be empty or purely whitespace");

        Properties emptyPropertyValue = new Properties();
        emptyPropertyValue.setProperty("nagios.nsca.host", StringUtils.EMPTY);

        NagiosSettingsFactory.createSettings(emptyPropertyValue);
    }

    @Test
    public void shouldThrowNagiosConfigurationExceptionForNonIntegerValueProvidedForIntegerValueKey() throws Exception {
        expectedException.expect(NagiosConfigurationException.class);
        expectedException.expectMessage("Key [nagios.nsca.timeout] must be an integer, was [notANumber]");

        Properties nonIntegerTimeout = new Properties();
        nonIntegerTimeout.setProperty("nagios.nsca.timeout", "notANumber");

        NagiosSettingsFactory.createSettings(nonIntegerTimeout);
    }

    @Test
    public void shouldThrowNagiosConfigurationExceptionForOutOfRangePort() throws Exception {
        expectedException.expect(NagiosConfigurationException.class);
        expectedException.expectMessage("Key [nagios.nsca.port] port must be between 1 and 65535 inclusive, was [65536]");

        Properties outOfRangePort = new Properties();
        outOfRangePort.setProperty("nagios.nsca.port", "65536");

        NagiosSettingsFactory.createSettings(outOfRangePort);
    }

    @Test
    public void shouldThrowNagiosConfigurationExceptionForUnknownEncryption() throws Exception {
        expectedException.expect(NagiosConfigurationException.class);
        expectedException.expectMessage("Key [nagios.nsca.encryption] must be one of [none,xor,des,triple_des,cast128,xtea,blowfish,twofish,rijndael128,rijndael192,rijndael256,serpent], was [foobar]");

        Properties unknownEncryption = new Properties();
        unknownEncryption.setProperty("nagios.nsca.encryption", "foobar");

        NagiosSettingsFactory.createSettings(unknownEncryption);
    }

}
