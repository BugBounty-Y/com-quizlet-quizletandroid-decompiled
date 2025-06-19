package com.quizlet.login.signupwall.viewmodel;

import androidx.lifecycle.Y;
import com.quizlet.eventlogger.features.authentication.SignUpWallEventLogger;
import com.quizlet.viewmodel.b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends b {
    public final SignUpWallEventLogger c;
    public final Y d;

    public a(SignUpWallEventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.c = eventLogger;
        this.d = new Y();
    }
}
