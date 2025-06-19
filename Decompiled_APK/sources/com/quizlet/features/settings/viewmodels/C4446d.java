package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.q0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* renamed from: com.quizlet.features.settings.viewmodels.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4446d extends C4447e implements q {
    public final com.quizlet.data.repository.qclass.c d;
    public final com.quizlet.shared.usecase.srs.a e;
    public final com.quizlet.features.emailconfirmation.logging.a f;
    public final com.quizlet.usecase.b g;
    public final s0 h;

    public C4446d(com.quizlet.data.repository.qclass.c userSettingsApiInteractor, com.quizlet.shared.usecase.srs.a changePasswordTupleMapper, com.quizlet.features.emailconfirmation.logging.a settingsEventLogger, com.quizlet.usecase.b passwordChangedEventMutator) {
        Intrinsics.checkNotNullParameter(userSettingsApiInteractor, "userSettingsApiInteractor");
        Intrinsics.checkNotNullParameter(changePasswordTupleMapper, "changePasswordTupleMapper");
        Intrinsics.checkNotNullParameter(settingsEventLogger, "settingsEventLogger");
        Intrinsics.checkNotNullParameter(passwordChangedEventMutator, "passwordChangedEventMutator");
        this.d = userSettingsApiInteractor;
        this.e = changePasswordTupleMapper;
        this.f = settingsEventLogger;
        this.g = passwordChangedEventMutator;
        this.h = e0.c(com.quizlet.features.settings.data.states.f.a);
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final q0 a() {
        return this.h;
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final void m(String password, String confirmPassword, String str) {
        Object value;
        Intrinsics.checkNotNullParameter(password, "password");
        Intrinsics.checkNotNullParameter(confirmPassword, "confirmPassword");
        s0 s0Var = this.h;
        if (!(s0Var.getValue() instanceof com.quizlet.features.settings.data.states.f) || str == null || StringsKt.O(str) || StringsKt.O(password) || StringsKt.O(confirmPassword)) {
            return;
        }
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.g.a));
        kotlinx.coroutines.E.A(p0.j(this), null, null, new C4445c(this, str, password, confirmPassword, null), 3);
    }

    @Override // com.quizlet.features.settings.viewmodels.q
    public final void t(String newPassword, String confirmPassword, String str) {
        s0 s0Var;
        Object value;
        com.quizlet.features.settings.data.models.a aVar;
        Intrinsics.checkNotNullParameter(newPassword, "newPassword");
        Intrinsics.checkNotNullParameter(confirmPassword, "confirmPassword");
        do {
            s0Var = this.h;
            value = s0Var.getValue();
            aVar = new com.quizlet.features.settings.data.models.a(newPassword, confirmPassword, str);
            this.e.getClass();
        } while (!s0Var.k(value, com.quizlet.shared.usecase.srs.a.w(aVar)));
    }
}
