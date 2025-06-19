package com.quizlet.features.setpage.viewmodel.selectedtermsmode;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.work.impl.model.v;
import com.quizlet.data.interactor.set.c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class b extends com.quizlet.viewmodel.a {
    public final c d;
    public final v e;
    public final long f;
    public final s0 g;

    public b(m0 savedStateHandle, c getTermsWithStarredUseCase, v setInSelectedTermsModeUseCase) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getTermsWithStarredUseCase, "getTermsWithStarredUseCase");
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeUseCase, "setInSelectedTermsModeUseCase");
        this.d = getTermsWithStarredUseCase;
        this.e = setInSelectedTermsModeUseCase;
        Long l = (Long) savedStateHandle.a("setId");
        this.f = l != null ? l.longValue() : 0L;
        this.g = e0.c(com.quizlet.features.setpage.terms.b.a);
        E.A(p0.j(this), null, null, new a(this, null), 3);
    }
}
