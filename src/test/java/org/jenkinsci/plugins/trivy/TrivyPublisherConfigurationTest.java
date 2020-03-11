package org.jenkinsci.plugins.trivy;

import jenkins.model.GlobalConfiguration;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import static org.junit.Assert.*;
import static org.powermock.api.support.membermodification.MemberMatcher.method;
import static org.powermock.api.support.membermodification.MemberModifier.suppress;

@RunWith(PowerMockRunner.class)
@PrepareForTest({GlobalConfiguration.class})
@PowerMockIgnore({"javax.crypto.*"})
public class TrivyPublisherConfigurationTest {

    @Before
    public void setup() {
        suppress(method(TrivyPublisherConfiguration.class, "save"));
    }

    @Test
    public void testGetScheme() {
        TrivyPublisherConfiguration config = new TrivyPublisherConfiguration();
        config.setUri("https://example.elasticsearch.com:8080");
        assertEquals("https", config.getScheme());
    }

    @Test
    public void testGetHost() {
        TrivyPublisherConfiguration config = new TrivyPublisherConfiguration();
        config.setUri("https://example.elasticsearch.com:8080");
        assertEquals("example.elasticsearch.com", config.getHost());
    }

    @Test
    public void testGetPort() {
        TrivyPublisherConfiguration config = new TrivyPublisherConfiguration();
        config.setUri("https://example.elasticsearch.com:8080");
        assertEquals(8080, config.getPort());
    }

    @Test
    public void testGetPortDefault() {
        TrivyPublisherConfiguration config = new TrivyPublisherConfiguration();
        config.setUri("https://example.elasticsearch.com/index-name");
        assertEquals(80, config.getPort());
    }

    @Test
    public void testGetIndex() {
        TrivyPublisherConfiguration config = new TrivyPublisherConfiguration();
        config.setUri("https://example.elasticsearch.com/index-name");
        assertEquals("index-name", config.getIndex());
    }
}
