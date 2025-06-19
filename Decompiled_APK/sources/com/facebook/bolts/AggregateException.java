package com.facebook.bolts;

import java.io.PrintStream;
import java.io.PrintWriter;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class AggregateException extends Exception {
    @Override // java.lang.Throwable
    public final void printStackTrace(PrintStream err) {
        Intrinsics.checkNotNullParameter(err, "err");
        super.printStackTrace(err);
        throw null;
    }

    @Override // java.lang.Throwable
    public final void printStackTrace(PrintWriter err) {
        Intrinsics.checkNotNullParameter(err, "err");
        super.printStackTrace(err);
        throw null;
    }
}
