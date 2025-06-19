package com.quizlet.login.magiclink.viewmodel;

import androidx.compose.material3.internal.H;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.J0;
import com.quizlet.data.model.EnumC4167t0;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class g extends w0 implements a, com.quizlet.features.infra.logout.viewmodels.a {
    public final com.quizlet.usecase.a b;
    public final com.quizlet.features.infra.logout.viewmodels.d c;
    public final s0 d;
    public final d0 e;
    public final J0 f;
    public String g;

    public g(com.quizlet.usecase.a userUseCase, com.quizlet.features.infra.logout.viewmodels.d logoutViewModelDelegate) {
        Intrinsics.checkNotNullParameter(userUseCase, "userUseCase");
        Intrinsics.checkNotNullParameter(logoutViewModelDelegate, "logoutViewModelDelegate");
        this.b = userUseCase;
        this.c = logoutViewModelDelegate;
        this.d = e0.c("");
        this.e = e0.b(0, 1, null, 5);
        this.f = new J0(new H(9, logoutViewModelDelegate.e, this), new c(this, null), 5);
        E.A(p0.j(this), null, null, new e(this, null), 3);
    }

    public final void A() {
        this.g = null;
        this.e.h(Unit.a);
    }

    @Override // com.quizlet.features.infra.logout.viewmodels.a
    public final void v(EnumC4167t0 warningType) {
        Intrinsics.checkNotNullParameter(warningType, "warningType");
        this.c.v(warningType);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        E.h(this.c.b, null);
    }
}
