package com.google.firebase.perf.metrics;

import android.view.ViewTreeObserver;

/* loaded from: classes2.dex */
public final class b implements ViewTreeObserver.OnDrawListener {
    public final /* synthetic */ AppStartTrace a;

    public b(AppStartTrace appStartTrace) {
        this.a = appStartTrace;
    }

    @Override // android.view.ViewTreeObserver.OnDrawListener
    public final void onDraw() {
        this.a.s++;
    }
}
