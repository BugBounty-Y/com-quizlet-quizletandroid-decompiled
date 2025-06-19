package com.google.gson;

import java.io.IOException;
import java.io.StringWriter;

/* loaded from: classes2.dex */
public abstract class m {
    public long a() {
        throw new UnsupportedOperationException(getClass().getSimpleName());
    }

    public String b() {
        throw new UnsupportedOperationException(getClass().getSimpleName());
    }

    public final String toString() {
        try {
            StringWriter stringWriter = new StringWriter();
            com.google.gson.stream.b bVar = new com.google.gson.stream.b(stringWriter);
            bVar.e = true;
            com.google.gson.internal.bind.m mVar = com.google.gson.internal.bind.p.a;
            com.google.gson.internal.bind.h.c(bVar, this);
            return stringWriter.toString();
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
