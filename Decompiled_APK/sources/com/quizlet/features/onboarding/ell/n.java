package com.quizlet.features.onboarding.ell;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.OnboardingELLEventLog;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final EventLogger a;

    public n(EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.a = eventLogger;
    }

    public final void a(OnboardingELLEventLog onboardingELLEventLog) {
        this.a.l(onboardingELLEventLog);
    }
}
