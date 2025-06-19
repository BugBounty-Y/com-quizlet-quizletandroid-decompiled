package com.fasterxml.jackson.core;

import java.io.IOException;

/* loaded from: classes.dex */
public abstract class JacksonException extends IOException {
    public JacksonException(String str) {
        super(str);
    }

    public abstract JsonLocation getLocation();

    public abstract String getOriginalMessage();

    public abstract Object getProcessor();

    public JacksonException(String str, Throwable th) {
        super(str, th);
    }
}
