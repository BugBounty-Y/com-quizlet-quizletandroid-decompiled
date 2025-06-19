package com.facebook.appevents.codeless;

import android.view.MotionEvent;
import android.view.View;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h implements View.OnTouchListener {
    public final com.facebook.appevents.codeless.internal.c a;
    public final WeakReference b;
    public final WeakReference c;
    public final View.OnTouchListener d;
    public final boolean e;

    public h(com.facebook.appevents.codeless.internal.c mapping, View rootView, View hostView) {
        Intrinsics.checkNotNullParameter(mapping, "mapping");
        Intrinsics.checkNotNullParameter(rootView, "rootView");
        Intrinsics.checkNotNullParameter(hostView, "hostView");
        this.a = mapping;
        this.b = new WeakReference(hostView);
        this.c = new WeakReference(rootView);
        this.d = com.facebook.appevents.codeless.internal.g.f(hostView);
        this.e = true;
    }

    @Override // android.view.View.OnTouchListener
    public final boolean onTouch(View view, MotionEvent motionEvent) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(motionEvent, "motionEvent");
        View view2 = (View) this.c.get();
        View view3 = (View) this.b.get();
        if (view2 != null && view3 != null && motionEvent.getAction() == 1) {
            c.c(this.a, view2, view3);
        }
        View.OnTouchListener onTouchListener = this.d;
        return onTouchListener != null && onTouchListener.onTouch(view, motionEvent);
    }
}
