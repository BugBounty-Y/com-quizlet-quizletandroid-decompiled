package com.google.firebase.perf.util;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewTreeObserver;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class e implements ViewTreeObserver.OnPreDrawListener {
    public final Handler a = new Handler(Looper.getMainLooper());
    public final AtomicReference b;
    public final com.google.firebase.perf.metrics.a c;
    public final com.google.firebase.perf.metrics.a d;

    public e(View view, com.google.firebase.perf.metrics.a aVar, com.google.firebase.perf.metrics.a aVar2) {
        this.b = new AtomicReference(view);
        this.c = aVar;
        this.d = aVar2;
    }

    @Override // android.view.ViewTreeObserver.OnPreDrawListener
    public final boolean onPreDraw() {
        View view = (View) this.b.getAndSet(null);
        if (view == null) {
            return true;
        }
        view.getViewTreeObserver().removeOnPreDrawListener(this);
        Handler handler = this.a;
        handler.post(this.c);
        handler.postAtFrontOfQueue(this.d);
        return true;
    }
}
