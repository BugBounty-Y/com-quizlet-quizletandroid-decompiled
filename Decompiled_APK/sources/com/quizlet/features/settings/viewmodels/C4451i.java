package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.q0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.features.settings.viewmodels.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4451i extends C4447e implements q {
    public final com.quizlet.data.repository.qclass.c d;
    public final com.quizlet.shared.usecase.srs.a e;
    public final com.quizlet.features.emailconfirmation.logging.a f;
    public final s0 g;
    public final String h;

    public C4451i(m0 savedStateHandle, com.quizlet.data.repository.qclass.c userSettingsApiInteractor, com.quizlet.shared.usecase.srs.a changePasswordTupleMapper, com.quizlet.features.emailconfirmation.logging.a settingsEventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(userSettingsApiInteractor, "userSettingsApiInteractor");
        Intrinsics.checkNotNullParameter(changePasswordTupleMapper, "changePasswordTupleMapper");
        Intrinsics.checkNotNullParameter(settingsEventLogger, "settingsEventLogger");
        this.d = userSettingsApiInteractor;
        this.e = changePasswordTupleMapper;
        this.f = settingsEventLogger;
        this.g = e0.c(com.quizlet.features.settings.data.states.f.a);
        Object objA = savedStateHandle.a("authToken");
        if (objA == null) {
            throw new IllegalArgumentException("Required value was null.");
        }
        this.h = (String) objA;
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final q0 a() {
        return this.g;
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final void m(String password, String confirmPassword, String str) {
        Object value;
        Intrinsics.checkNotNullParameter(password, "password");
        Intrinsics.checkNotNullParameter(confirmPassword, "confirmPassword");
        s0 s0Var = this.g;
        if (!(s0Var.getValue() instanceof com.quizlet.features.settings.data.states.f) || StringsKt.O(password) || StringsKt.O(confirmPassword)) {
            return;
        }
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.g.a));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4450h(this, this.h, password, confirmPassword, null), 3);
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final void t(String newPassword, String confirmPassword, String str) {
        s0 s0Var;
        Object value;
        com.quizlet.features.settings.data.models.a aVar;
        Intrinsics.checkNotNullParameter(newPassword, "newPassword");
        Intrinsics.checkNotNullParameter(confirmPassword, "confirmPassword");
        do {
            s0Var = this.g;
            value = s0Var.getValue();
            aVar = new com.quizlet.features.settings.data.models.a(newPassword, confirmPassword, null);
            this.e.getClass();
        } while (!s0Var.k(value, com.quizlet.shared.usecase.srs.a.w(aVar)));
    }
}
