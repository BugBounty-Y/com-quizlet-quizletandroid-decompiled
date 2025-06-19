package com.quizlet.features.setpage.header.viewmodel;

import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import com.google.firebase.messaging.p;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class f extends com.quizlet.viewmodel.a implements a {
    public final io.ktor.client.plugins.api.d d;
    public final p e;
    public final G f;
    public final s0 g;
    public final d0 h;
    public final long i;
    public y0 j;

    public f(m0 savedStateHandle, io.ktor.client.plugins.api.d getStudySetUseCase, p setPageLogger, G setPageStudyModesManager, SetPagePerformanceLogger setPagePerformanceLogger) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(getStudySetUseCase, "getStudySetUseCase");
        Intrinsics.checkNotNullParameter(setPageLogger, "setPageLogger");
        Intrinsics.checkNotNullParameter(setPageStudyModesManager, "setPageStudyModesManager");
        Intrinsics.checkNotNullParameter(setPagePerformanceLogger, "setPagePerformanceLogger");
        this.d = getStudySetUseCase;
        this.e = setPageLogger;
        this.f = setPageStudyModesManager;
        this.g = e0.c(com.quizlet.features.setpage.header.data.d.g);
        this.h = e0.b(0, 0, null, 7);
        Long l = (Long) savedStateHandle.a("setId");
        this.i = l != null ? l.longValue() : 0L;
        setPagePerformanceLogger.i();
        E.A(p0.j(this), null, null, new c(this, null), 3);
    }

    @Override // com.quizlet.viewmodel.a, com.quizlet.viewmodel.b, androidx.lifecycle.w0
    public final void z() {
        super.z();
        y0 y0Var = this.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.j = null;
    }
}
