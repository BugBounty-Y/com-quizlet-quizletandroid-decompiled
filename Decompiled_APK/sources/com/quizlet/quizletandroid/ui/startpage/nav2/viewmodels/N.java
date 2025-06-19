package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.lifecycle.X;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class N extends com.quizlet.viewmodel.b {
    public final com.quizlet.features.infra.basestudy.manager.d c;
    public final long d;
    public final int e;
    public final X f;

    public N(com.quizlet.features.infra.basestudy.manager.d studyFunnelEventManager, long j, int i) {
        Intrinsics.checkNotNullParameter(studyFunnelEventManager, "studyFunnelEventManager");
        this.c = studyFunnelEventManager;
        this.d = j;
        this.e = i;
        this.f = new X(1);
    }
}
