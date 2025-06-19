package com.quizlet.search.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.search.data.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final EventLogger a;
    public d b;

    public b(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
        this.b = new d("", "");
    }
}
