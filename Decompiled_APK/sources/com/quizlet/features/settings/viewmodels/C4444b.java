package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.features.settings.viewmodels.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4444b extends C4447e implements l {
    public final com.quizlet.data.repository.qclass.c d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final s0 f;
    public final String g;
    public final d0 h;

    public C4444b(m0 savedStateHandle, com.quizlet.data.repository.qclass.c userSettingsApiInteractor, com.quizlet.features.emailconfirmation.logging.a settingsEventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(userSettingsApiInteractor, "userSettingsApiInteractor");
        Intrinsics.checkNotNullParameter(settingsEventLogger, "settingsEventLogger");
        this.d = userSettingsApiInteractor;
        this.e = settingsEventLogger;
        this.f = e0.c(com.quizlet.features.settings.data.states.b.a);
        Object objA = savedStateHandle.a("authToken");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = (String) objA;
        this.h = e0.b(0, 1, null, 5);
    }

    public final void B(String newEmail) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(newEmail, "newEmail");
        do {
            s0Var = this.f;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.c.a));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4443a(this, newEmail, null), 3);
    }
}
