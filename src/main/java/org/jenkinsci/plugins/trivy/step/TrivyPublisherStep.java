package org.jenkinsci.plugins.trivy.step;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.stream.JsonReader;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import jenkins.tasks.SimpleBuildStep;
import org.apache.http.HttpHost;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.trivy.TrivyPublisherConfiguration;
import org.jenkinsci.plugins.trivy.model.TrivyTarget;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public class TrivyPublisherStep extends Builder implements SimpleBuildStep {

//    TODO: Support console log level

    private static final Logger LOG = Logger.getLogger(TrivyPublisherStep.class.getName());

    private String report;

    @DataBoundConstructor
    public TrivyPublisherStep(String report) {
        this.report = report;
    }

    public String getReport() {
        return report;
    }

    @DataBoundSetter
    public void setReport(String report) {
        this.report = report;
    }

    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull Launcher launcher, @Nonnull TaskListener listener) throws InterruptedException, IOException {
        FilePath filePath = new FilePath(workspace, report);
        long start = System.currentTimeMillis();
        InputStreamReader inputStream = new InputStreamReader(filePath.read(), StandardCharsets.UTF_8);
        JsonReader jsonReader = new JsonReader(inputStream);
        jsonReader.beginArray();
        Gson gson = new GsonBuilder().create();
        TrivyTarget target = null;
        while (jsonReader.hasNext()) {
            target = gson.fromJson(jsonReader, TrivyTarget.class);
        }
        jsonReader.endArray();
        long end = System.currentTimeMillis();
        LOG.fine(String.format("Reading trivy report took {0:C2} seconds", (end - start) / 1000));
        TrivyPublisherConfiguration config = TrivyPublisherConfiguration.get();
        listener.getLogger().println("Host: " + config.getHost() + " port: " + config.getPort() + " scheme: " + config.getScheme());
        if (target != null) {

            RestHighLevelClient elasticsearch = new RestHighLevelClient(
                RestClient.builder(new HttpHost(config.getHost(), config.getPort(), config.getScheme()))
            );
            IndexRequest indexRequest = new IndexRequest(config.getIndex()).source(target);
            IndexResponse response = elasticsearch.index(indexRequest, RequestOptions.DEFAULT);
            listener.getLogger().println(response.toString());
        }
    }

    @Symbol("trivyPublisher")
    @Extension
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public DescriptorImpl() {
            load();
        }

        @Nonnull
        @Override
        public String getDisplayName() {
            return "Trivy Scanning Publisher Step";
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> jobType) {
            return true;
        }
    }
}
