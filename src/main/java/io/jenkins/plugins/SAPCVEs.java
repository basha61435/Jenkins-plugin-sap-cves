package io.jenkins.plugins;

import hudson.Extension;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import java.util.Set;

public class SAPCVEs extends Step {
    private String path;

    @DataBoundConstructor
    public SAPCVEs(String path) {
        this.path = path;
    }

    @DataBoundSetter
    public void setPath(String path) {
        this.path = path;
    }

    public String getPath() {
        return path;
    }
   public SAPCVEs() {
   }

    @Override
    public StepExecution start(StepContext stepContext) throws Exception {
        return new ValidateCVEsExcecution(this, stepContext);
    }

    @Extension
    public static class DescriptorImpl extends StepDescriptor {
        @Override
        public String getFunctionName() {
            return "validateCVEs";
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of();
        }
    }
}
