package com.google.firebase.perf.util;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewTreeObserver;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements ViewTreeObserver.OnGlobalLayoutListener {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ View b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(View view, C4899s c4899s) {
        this.b = view;
        this.c = c4899s;
    }

    @Override // android.view.ViewTreeObserver.OnGlobalLayoutListener
    public final void onGlobalLayout() {
        switch (this.a) {
            case 0:
                b bVar = (b) this.c;
                bVar.getClass();
                this.b.getViewTreeObserver().removeOnDrawListener(bVar);
                break;
            default:
                Rect rect = new Rect();
                View view = this.b;
                view.getWindowVisibleDisplayFrame(rect);
                int height = view.getRootView().getHeight();
                double d = height - rect.bottom;
                double d2 = height * 0.15d;
                C4899s c4899s = (C4899s) this.c;
                if (d <= d2) {
                    c4899s.c(com.quizlet.qutils.android.a.b);
                    break;
                } else {
                    c4899s.c(com.quizlet.qutils.android.a.a);
                    break;
                }
        }
    }

    public /* synthetic */ a(b bVar, View view) {
        this.c = bVar;
        this.b = view;
    }
}
