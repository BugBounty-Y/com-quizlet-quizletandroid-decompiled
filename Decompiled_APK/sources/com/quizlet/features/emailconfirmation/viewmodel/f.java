package com.quizlet.features.emailconfirmation.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.paging.J0;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.quizletandroid.interactor.t;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class f extends w0 implements g, com.quizlet.features.infra.logout.viewmodels.a {
    public final t b;
    public final com.google.firebase.crashlytics.internal.common.j c;
    public final com.quizlet.features.infra.logout.viewmodels.d d;
    public final com.quizlet.features.emailconfirmation.logging.a e;
    public final s0 f;
    public final d0 g;
    public final d0 h;
    public final d0 i;

    public f(t loggedInUserInteractor, com.google.firebase.crashlytics.internal.common.j resendConfirmationEmailUseCase, com.quizlet.features.infra.logout.viewmodels.d logoutViewModelDelegate, com.quizlet.features.emailconfirmation.logging.a logger) {
        Intrinsics.checkNotNullParameter(loggedInUserInteractor, "loggedInUserInteractor");
        Intrinsics.checkNotNullParameter(resendConfirmationEmailUseCase, "resendConfirmationEmailUseCase");
        Intrinsics.checkNotNullParameter(logoutViewModelDelegate, "logoutViewModelDelegate");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = loggedInUserInteractor;
        this.c = resendConfirmationEmailUseCase;
        this.d = logoutViewModelDelegate;
        this.e = logger;
        this.f = e0.c(new com.quizlet.features.emailconfirmation.data.states.a());
        this.g = e0.b(0, 1, null, 5);
        this.h = e0.b(0, 0, null, 7);
        this.i = e0.b(0, 1, null, 5);
        E.A(p0.j(this), null, null, new b(this, null), 3);
        e0.w(new J0(logoutViewModelDelegate.e, new a(this, null), 5), p0.j(this));
    }

    @Override // com.quizlet.features.infra.logout.viewmodels.a
    public final void v(EnumC4167t0 warningType) {
        Intrinsics.checkNotNullParameter(warningType, "warningType");
        this.d.v(warningType);
    }

    @Override // androidx.lifecycle.w0
    public final void z() {
        E.h(this.d.b, null);
    }
}
