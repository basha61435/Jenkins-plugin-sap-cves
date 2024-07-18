package io.jenkins.plugins;

import hudson.model.TaskListener;
import io.jenkins.plugins.Model.JavaCVEs;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;

import javax.annotation.Nonnull;
import java.io.Serializable;
import java.util.List;

public class ValidateCVEsExcecution extends SynchronousNonBlockingStepExecution<List<JavaCVEs>> implements Serializable {

    private static final long serialVersionUID = 1L;
    private transient SAPCVEs sapcvEs;

    protected ValidateCVEsExcecution(SAPCVEs sapcvEs, StepContext context) {
        super(context);
        this.sapcvEs = sapcvEs;
    }

    @Override
    protected List<JavaCVEs> run() throws Exception {
        TaskListener listener = getContext().get(TaskListener.class);
        FindFiles findFiles = new FindFiles();
        List<JavaCVEs> javaCVEsList = findFiles.getJavaCVEs(sapcvEs.getPath());
        listener.getLogger().println("path: " + sapcvEs.getPath());
        listener.getLogger().println("cves: " + javaCVEsList);
        return javaCVEsList;
    }

}
