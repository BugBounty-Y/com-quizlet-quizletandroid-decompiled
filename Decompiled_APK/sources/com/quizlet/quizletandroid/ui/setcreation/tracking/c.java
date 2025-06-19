package com.quizlet.quizletandroid.ui.setcreation.tracking;

import com.quizlet.eventlogger.EventLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final EventLogger a;

    public c(EventLogger logger) {
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.a = logger;
    }

    public final void a(a errorType) {
        Intrinsics.checkNotNullParameter(errorType, "errorType");
        this.a.k(errorType.a);
    }
}
