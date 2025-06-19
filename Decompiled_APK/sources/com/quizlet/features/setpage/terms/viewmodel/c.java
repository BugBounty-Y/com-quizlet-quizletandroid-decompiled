package com.quizlet.features.setpage.terms.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.features.setpage.terms.f;
import com.quizlet.infra.legacysyncengine.datasources.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends com.quizlet.viewmodel.a {
    public final com.quizlet.data.interactor.set.c d;
    public final com.quizlet.data.repository.qclass.c e;
    public final com.quizlet.db.a f;
    public final SetPagePerformanceLogger g;
    public final s0 h;
    public final long i;
    public final w j;

    public c(m0 savedStateHandle, com.quizlet.infra.legacysyncengine.datasources.factory.b dataSourceFactory, com.quizlet.data.interactor.set.c getTermsWithStarredUseCase, com.quizlet.data.repository.qclass.c getDiagramDataUseCase, com.quizlet.db.a globalSharedPreferencesManager, SetPagePerformanceLogger setPagePerformanceLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(dataSourceFactory, "dataSourceFactory");
        Intrinsics.checkNotNullParameter(getTermsWithStarredUseCase, "getTermsWithStarredUseCase");
        Intrinsics.checkNotNullParameter(getDiagramDataUseCase, "getDiagramDataUseCase");
        Intrinsics.checkNotNullParameter(globalSharedPreferencesManager, "globalSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        this.d = getTermsWithStarredUseCase;
        this.e = getDiagramDataUseCase;
        this.f = globalSharedPreferencesManager;
        this.g = setPagePerformanceLogger;
        this.h = e0.c(new f((List) null, 3));
        Long l = (Long) savedStateHandle.a("setId");
        long jLongValue = l != null ? l.longValue() : 0L;
        this.i = jLongValue;
        this.j = dataSourceFactory.a(jLongValue);
        setPagePerformanceLogger.k();
        setPagePerformanceLogger.h();
        B(false);
    }

    public final void B(boolean z) {
        E.A(p0.j(this), null, null, new a(this, z, null), 3);
        E.A(p0.j(this), null, null, new b(this, null), 3);
    }
}
