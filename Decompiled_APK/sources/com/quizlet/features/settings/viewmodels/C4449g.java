package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.features.settings.viewmodels.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4449g extends C4447e {
    public final com.quizlet.data.repository.qclass.c d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final s0 f;
    public final String g;

    public C4449g(m0 savedStateHandle, com.quizlet.data.repository.qclass.c userSettingsApiInteractor, com.quizlet.features.emailconfirmation.logging.a settingsEventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(userSettingsApiInteractor, "userSettingsApiInteractor");
        Intrinsics.checkNotNullParameter(settingsEventLogger, "settingsEventLogger");
        this.d = userSettingsApiInteractor;
        this.e = settingsEventLogger;
        this.f = e0.c(com.quizlet.features.settings.data.states.j.a);
        Object objA = savedStateHandle.a("authToken");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.g = (String) objA;
    }

    public final void B(String newUsername) {
        s0 s0Var;
        Object value;
        Intrinsics.checkNotNullParameter(newUsername, "newUsername");
        do {
            s0Var = this.f;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.k.a));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4448f(this, newUsername, null), 3);
    }
}
