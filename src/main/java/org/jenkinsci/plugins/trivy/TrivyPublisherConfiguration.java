package org.jenkinsci.plugins.trivy;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.Extension;
import hudson.model.Item;
import hudson.security.ACL;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.interceptor.RequirePOST;

import javax.annotation.Nonnull;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials;

/**
 * @author nthienan.it
 */
@Extension
public class TrivyPublisherConfiguration extends GlobalConfiguration {

    public static final String DEFAULT_INDEX = "trivy-scanning-result";

    private String name;
    private String uri;
    private String credentialId;

    @DataBoundConstructor
    public TrivyPublisherConfiguration() {
    }

    /**
     * Convenience method to get configuration object
     *
     * @return the configuration object
     */
    public static TrivyPublisherConfiguration get() {
        return GlobalConfiguration.all().get(TrivyPublisherConfiguration.class);
    }

    public static <T extends Credentials> T getCredentials(@Nonnull Class<T> type, @Nonnull String credentialsId) {
        return CredentialsMatchers.firstOrNull(lookupCredentials(
            type, Jenkins.get(), ACL.SYSTEM, Collections.emptyList()),
            CredentialsMatchers.allOf(
                CredentialsMatchers.withId(credentialsId),
                CredentialsMatchers.instanceOf(type)
            )
        );
    }

    public String getCredentialId() {
        return credentialId;
    }

    @DataBoundSetter
    public void setCredentialId(String credentialId) {
        this.credentialId = credentialId;
        save();
    }

    public String getName() {
        return name;
    }

    @DataBoundSetter
    public void setName(String name) {
        this.name = name;
        save();
    }

    public String getUri() {
        return uri;
    }

    @DataBoundSetter
    public void setUri(String uri) {
        this.uri = uri;
        save();
    }

    @Nonnull
    @Override
    public String getDisplayName() {
        return "Trivy Scanning Publisher Configuration";
    }

    @Override
    public boolean configure(StaplerRequest req, JSONObject json) throws FormException {
        req.bindJSON(this, json);
        return true;
    }

    /**
     * Fills the list box in the settings page with valid credentials.
     *
     * @param credentialsId the current credentials id
     * @return ListBoxModel containing credentials to show
     */
    @SuppressWarnings("unused") // used by Jelly
    public ListBoxModel doFillCredentialIdItems(@QueryParameter String credentialsId) {
        if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
            return new StandardListBoxModel().includeCurrentValue(credentialsId);
        }
        return new StandardListBoxModel()
            .includeEmptyValue()
            .includeMatchingAs(
                ACL.SYSTEM,
                Jenkins.get(),
                StandardCredentials.class,
                Collections.emptyList(),
                CredentialsMatchers.anyOf(CredentialsMatchers.instanceOf(StandardUsernamePasswordCredentials.class)))
            .includeCurrentValue(credentialsId);
    }

    /**
     * Validates the credential id.
     *
     * @param item  context for validation
     * @param value to validate
     * @return FormValidation
     */
    @SuppressWarnings("unused") // used by Jelly
    public FormValidation doCheckCredentialId(@AncestorInPath Item item, @QueryParameter String value) {
        if (item == null) {
            if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                return FormValidation.ok();
            }
        } else {
            if (!item.hasPermission(Item.EXTENDED_READ)
                && !item.hasPermission(CredentialsProvider.USE_ITEM)) {
                return FormValidation.ok();
            }
        }
        if (StringUtils.isEmpty(value)) {
            return FormValidation.ok();
        }
        if (null == getCredentials(UsernamePasswordCredentials.class, value)) {
            return FormValidation.error("Cannot find currently selected credentials");
        }
        return FormValidation.ok();
    }

    @SuppressWarnings("unused") // used by Jelly
    public FormValidation doCheckUri(@AncestorInPath Item item, @QueryParameter String value) {
        try {
            if (StringUtils.isNotBlank(value)) {
                new URL(value);
            }
        } catch (MalformedURLException e) {
            return FormValidation.error("Invalid URL");
        }
        return FormValidation.ok();
    }

    @SuppressWarnings("unused") // used by Jelly
    public FormValidation doCheckName(@AncestorInPath Item item, @QueryParameter String value) {
        if (StringUtils.isBlank(value)) {
            return FormValidation.error("Name must not be empty");
        }
        return FormValidation.ok();
    }

    @RequirePOST
    @SuppressWarnings("unused") //used by Jelly
    public FormValidation doTestConnection(@QueryParameter String uri, @QueryParameter String credentialId) {
        if (StringUtils.isBlank(uri) || StringUtils.isBlank(credentialId)) {
            return FormValidation.error("URI or Credential is blank");
        }
        return FormValidation.ok("Connection is verified successfully");
    }

    @Nonnull
    public String getScheme() {
        if (StringUtils.isNotBlank(uri)) {
            Pattern pattern = getURIPattern();
            Matcher matcher = pattern.matcher(uri);
            if (matcher.matches()) {
                return matcher.group(1);
            }
        }
        return "";
    }

    @Nonnull
    public String getHost() {
        if (StringUtils.isNotBlank(uri)) {
            Pattern pattern = getURIPattern();
            Matcher matcher = pattern.matcher(uri);
            if (matcher.matches()) {
                return matcher.group(2);
            }
        }
        return "";
    }

    @Nonnull
    public int getPort() {
        if (StringUtils.isNotBlank(uri)) {
            Pattern pattern = getURIPattern();
            Matcher matcher = pattern.matcher(uri);
            if (matcher.matches()) {
                return Integer.parseInt(matcher.group(3));
            } else {
                return 80;
            }
        }
        return 9200;
    }

    @Nonnull
    public String getIndex() {
        if (StringUtils.isNotBlank(uri)) {
            Pattern pattern = getURIPattern();
            Matcher matcher = pattern.matcher(uri);
            if (matcher.matches()) {
                return matcher.group(5);
            }
        }
        return DEFAULT_INDEX;
    }

    private Pattern getURIPattern() {
        return Pattern.compile("^(.*)://([A-Za-z0-9\\-\\.]+):([0-9]+)?([^/].*)$");
    }
}
