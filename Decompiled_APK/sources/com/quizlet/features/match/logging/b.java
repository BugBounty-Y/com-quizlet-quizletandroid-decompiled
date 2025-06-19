package com.quizlet.features.match.logging;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.infra.basestudy.manager.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final f a;
    public final a b;
    public final EventLogger c;

    public b(f studyModeManager, a questionEventLogger, EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(studyModeManager, "studyModeManager");
        Intrinsics.checkNotNullParameter(questionEventLogger, "questionEventLogger");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = studyModeManager;
        this.b = questionEventLogger;
        this.c = eventLogger;
    }
}
