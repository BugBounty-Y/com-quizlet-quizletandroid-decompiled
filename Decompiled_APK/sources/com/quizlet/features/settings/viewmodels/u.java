package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.p0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class u extends C4447e implements o {
    public final com.quizlet.data.repository.qclass.c d;
    public final s0 e;
    public com.quizlet.features.settings.data.models.b f;

    public u(com.quizlet.data.repository.qclass.c userSettingsApiInteractor) {
        Intrinsics.checkNotNullParameter(userSettingsApiInteractor, "userSettingsApiInteractor");
        this.d = userSettingsApiInteractor;
        this.e = e0.c(new com.quizlet.features.settings.data.states.u(null));
    }

    public static final void B(u uVar, String str) {
        s0 s0Var;
        Object value;
        do {
            s0Var = uVar.e;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.settings.data.states.w(str, uVar.f)));
    }

    public final void C(String password) {
        Intrinsics.checkNotNullParameter(password, "password");
        D();
        if (StringsKt.O(password)) {
            return;
        }
        E();
        kotlinx.coroutines.E.A(p0.j(this), null, null, new t(this, password, null), 3);
    }

    public final void D() {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.e;
            value = s0Var.getValue();
        } while (!s0Var.k(value, new com.quizlet.features.settings.data.states.u(this.f)));
    }

    public final void E() {
        s0 s0Var;
        Object value;
        do {
            s0Var = this.e;
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.features.settings.data.states.v.a));
    }
}
