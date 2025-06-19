package com.quizlet.learn.logging;

import com.quizlet.eventlogger.EventLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public final EventLogger a;

    public d(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }
}
