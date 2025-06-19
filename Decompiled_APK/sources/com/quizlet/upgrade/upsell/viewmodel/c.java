package com.quizlet.upgrade.upsell.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import androidx.work.impl.model.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 {
    public final e b;
    public final s0 c;
    public final d0 d;

    public c(e userHasFreeTrialUseCase) {
        Intrinsics.checkNotNullParameter(userHasFreeTrialUseCase, "userHasFreeTrialUseCase");
        this.b = userHasFreeTrialUseCase;
        this.c = e0.c(Boolean.FALSE);
        this.d = e0.b(0, 0, null, 7);
        E.A(p0.j(this), null, null, new a(this, null), 3);
    }
}
