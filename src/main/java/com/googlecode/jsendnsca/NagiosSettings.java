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

import static com.googlecode.jsendnsca.encryption.Encryption.NONE;
import static org.apache.commons.lang.StringUtils.defaultIfEmpty;
import static org.apache.commons.lang.builder.ToStringStyle.SHORT_PREFIX_STYLE;

import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.math.IntRange;

import com.googlecode.jsendnsca.encryption.Encryption;
import com.googlecode.jsendnsca.encryption.Encryptor;

/**
 * The settings to use for sending the Passive Check
 *
 * @author Raj.Patel
 * @version 1.0
 * @see com.googlecode.jsendnsca.builders.NagiosSettingsBuilder
 */
public class NagiosSettings {

    private static final int MIN_PORT = 1;
    private static final int MAX_PORT = 65535;
    private static final String INVALID_PORT_MESSAGE = String.format("port must be between %s and %s inclusive", MIN_PORT, MAX_PORT);
    private static final int SMALL_MAX_MESSAGE_SIZE_IN_CHARS = 512;
    private static final int LARGE_MAX_MESSAGE_SIZE_IN_CHARS = 4096;

    private String nagiosHost = "localhost";
    private String password = "";
    private int port = 5667;
    private int timeout = 10000;
    private int connectTimeout = 5000;
    private Encryptor encryptor = NONE.getEncryptor();
    private int maxMessageSizeInChars = SMALL_MAX_MESSAGE_SIZE_IN_CHARS;

    /**
     * The connection timeout
     *
     * @return timeout in ms
     */
    public int getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * The {@link Encryptor} used to encrypt the passive check
     *
     * @return the {@link Encryptor}
     */
    public Encryptor getEncryptor() {
        return encryptor;
    }

    /**
     * The host or IP of the Nagios host running the NSCA add-on
     *
     * @return the host or IP, defaults to localhost
     */
    public String getNagiosHost() {
        return nagiosHost;
    }

    /**
     * The password configured in the ncsa.cfg file used by NSCA
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }

    /**
     * The port on which NSCA is listening
     *
     * @return the port, defaults to 5667
     */
    public int getPort() {
        return port;
    }

    /**
     * The socket timeout to use when sending the passive check
     *
     * @return the timeout in ms, defaults to 10000 ms
     */
    public int getTimeout() {
        return timeout;
    }

    /**
     * Set the connection timeout, default is 5000 ms
     *
     * @param connectTimeout
     *            timeout in ms
     */
    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    /**
     * The {@link Encryption} to use to encrypt the passive check
     *
     * @param encryption
     *             encryption algorithm
     */
    public void setEncryption(Encryption encryption) {
        setEncryptor(encryption.getEncryptor());
    }

    /**
     * The {@link Encryptor} to use to encrypt the passive check
     *
     * @param encryptor
     *            message encryptor
     */
    public void setEncryptor(Encryptor encryptor) {
        Validate.notNull(encryptor, "encryptor cannot be null");
        this.encryptor = encryptor;
    }

    /**
     * The host or IP of the Nagios host running the NSCA add-on
     *
     * @param nagiosHost
     *            the host or IP, defaults to localhost
     */
    public void setNagiosHost(String nagiosHost) {
        Validate.notEmpty(nagiosHost, "nagiosHost cannot be null or empty");
        this.nagiosHost = nagiosHost;
    }

    /**
     * The password configured in the ncsa.cfg file used by NSCA
     *
     * @param password
     *            the password
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * The port on which NSCA is listening
     *
     * @param port
     *            the port, defaults to 5667
     */
    public void setPort(int port) {
        Validate.isTrue(validPortRange(port), INVALID_PORT_MESSAGE);
        this.port = port;
    }

    /**
     * The socket timeout to use when sending the passive check
     *
     * @param timeout
     *            the timeout in ms, defaults to 10000 ms
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    /**
     * Leverage support NSCA 2.9.1 for longer messages of 4096 chars
     * instead of previous limit of 512 chars.
     */
    public void enableLargeMessageSupport() {
        maxMessageSizeInChars = LARGE_MAX_MESSAGE_SIZE_IN_CHARS;
    }

    /**
     * The maximum number of chars in message sent to NSCA before
     * the message is truncated
     *
     * see enableLargeMessageSupport
     * @return number of chars
     */
    public int getMaxMessageSizeInChars() {
        return maxMessageSizeInChars;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(19, 55)
            .append(nagiosHost)
            .append(port)
            .append(password)
            .append(timeout)
            .append(connectTimeout)
            .append(encryptor)
            .toHashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) { return false; }
        if (obj == this) { return true; }
        if (obj.getClass() != getClass()) {
          return false;
        }
        NagiosSettings rhs = (NagiosSettings) obj;

        return new EqualsBuilder()
            .append(nagiosHost, rhs.nagiosHost)
            .append(port, rhs.port)
            .append(password, rhs.password)
            .append(timeout, rhs.timeout)
            .append(connectTimeout, rhs.connectTimeout)
            .append(encryptor, rhs.encryptor)
            .isEquals();
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return new ToStringBuilder(this, SHORT_PREFIX_STYLE)
            .append("nagiosHost", nagiosHost)
            .append("port", port)
            .append("password", password)
            .append("timeout", timeout)
            .append("connectTimeout", connectTimeout)
            .append("encryptor", defaultIfEmpty(encryptor.getClass().getSimpleName(), "none"))
            .toString();
    }

    private static boolean validPortRange(int port) {
        return new IntRange(MIN_PORT, MAX_PORT).containsInteger(port);
    }
}