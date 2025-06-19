package com.quizlet.features.flashcards.logging;

import assistantMode.enums.m;
import com.quizlet.eventlogger.EventLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final EventLogger a;

    public d(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public static void a(d dVar, String str, Boolean bool, Boolean bool2, m mVar, int i) {
        dVar.a.n(str, null, null, (i & 8) != 0 ? null : bool, (i & 16) != 0 ? null : bool2, (i & 32) != 0 ? null : mVar);
    }
}
