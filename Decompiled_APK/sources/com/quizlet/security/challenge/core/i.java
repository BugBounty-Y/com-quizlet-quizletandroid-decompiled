package com.quizlet.security.challenge.core;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final Context a;
    public final kotlinx.coroutines.internal.d b;
    public final com.quizlet.usecase.a c;
    public final com.quizlet.usecase.a d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final com.quizlet.usecase.a f;
    public int g;
    public long h;

    public i(Context appContext, kotlinx.coroutines.internal.d defaultScope, com.quizlet.usecase.a shouldShowSecurityChallenge, com.quizlet.usecase.a securityChallengeDetected, com.quizlet.features.emailconfirmation.logging.a eventLogger, com.quizlet.usecase.a userUseCase) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(defaultScope, "defaultScope");
        Intrinsics.checkNotNullParameter(shouldShowSecurityChallenge, "shouldShowSecurityChallenge");
        Intrinsics.checkNotNullParameter(securityChallengeDetected, "securityChallengeDetected");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(userUseCase, "userUseCase");
        this.a = appContext;
        this.b = defaultScope;
        this.c = shouldShowSecurityChallenge;
        this.d = securityChallengeDetected;
        this.e = eventLogger;
        this.f = userUseCase;
    }
}
