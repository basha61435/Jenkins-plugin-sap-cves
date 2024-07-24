package io.jenkins.plugins;

import hudson.model.TaskListener;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import javax.annotation.Nonnull;

public class DummyTaskListener implements TaskListener {
    private final PrintStream printStream;

    // Constructor to initialize the PrintStream
    public DummyTaskListener() {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        this.printStream = new PrintStream(byteArrayOutputStream);
    }

    @Nonnull
    @Override
    public PrintStream getLogger() {
        return printStream;
    }

    // Method to get the captured output from the PrintStream
    public String getOutput() {
        return printStream.toString();
    }
}

