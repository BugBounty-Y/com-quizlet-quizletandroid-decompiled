package com.comscore.streaming;

import com.comscore.util.cpp.CppJavaBinder;
import java.lang.ref.WeakReference;
import java.util.Map;

/* loaded from: classes.dex */
public class StreamingPublisherConfiguration extends CppJavaBinder {
    private WeakReference<StreamingConfiguration> b;
    private String c;

    public StreamingPublisherConfiguration(StreamingConfiguration streamingConfiguration, String str) {
        this.b = new WeakReference<>(streamingConfiguration);
        this.c = str;
    }

    private native void addLabelsNative(long j, String str, Map<String, String> map);

    private native void removeAllLabelsNative(long j, String str);

    private native void removeLabelNative(long j, String str, String str2);

    private native void setLabelNative(long j, String str, String str2, String str3);

    public void addLabels(Map<String, String> map) {
        try {
            StreamingConfiguration streamingConfiguration = this.b.get();
            if (streamingConfiguration == null) {
                return;
            }
            addLabelsNative(streamingConfiguration.a(), this.c, map);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
        }
    }

    @Override // com.comscore.util.cpp.CppJavaBinder
    public void destroyCppObject() {
    }

    public void removeAllLabels() {
        try {
            StreamingConfiguration streamingConfiguration = this.b.get();
            if (streamingConfiguration == null) {
                return;
            }
            removeAllLabelsNative(streamingConfiguration.a(), this.c);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
        }
    }

    public void removeLabel(String str) {
        try {
            StreamingConfiguration streamingConfiguration = this.b.get();
            if (streamingConfiguration == null) {
                return;
            }
            removeLabelNative(streamingConfiguration.a(), this.c, str);
        } catch (UnsatisfiedLinkError e) {
            printException(e);
        }
    }

    public void setLabel(String str, String str2) {
        try {
            StreamingConfiguration streamingConfiguration = this.b.get();
            if (streamingConfiguration == null) {
                return;
            }
            try {
                setLabelNative(streamingConfiguration.a(), this.c, str, str2);
            } catch (UnsatisfiedLinkError e) {
                e = e;
                printException(e);
            }
        } catch (UnsatisfiedLinkError e2) {
            e = e2;
        }
    }
}
