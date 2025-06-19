package com.quizlet.search.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class M extends w0 {
    public final androidx.work.impl.model.e b;
    public final com.quizlet.data.interactor.set.c c;
    public final SearchEventLogger d;
    public final TermSearchUiModel e;
    public final s0 f;
    public final d0 g;
    public final Y h;
    public boolean i;
    public final C4203d j;

    public M(m0 savedStateHandle, androidx.work.impl.model.e termsUseCase, com.quizlet.data.interactor.set.c userUseCase, SearchEventLogger searchEventLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(termsUseCase, "termsUseCase");
        Intrinsics.checkNotNullParameter(userUseCase, "userUseCase");
        Intrinsics.checkNotNullParameter(searchEventLogger, "searchEventLogger");
        this.b = termsUseCase;
        this.c = userUseCase;
        this.d = searchEventLogger;
        Object objA = savedStateHandle.a("term_data");
        if (objA == null) {
            throw new IllegalArgumentException("Can't have null info passed as parameter for term search");
        }
        this.e = (TermSearchUiModel) objA;
        this.f = e0.c(com.quizlet.search.data.term.g.a);
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.g = d0VarB;
        this.h = new Y(d0VarB);
        this.i = true;
        this.j = new C4203d(this);
    }
}
