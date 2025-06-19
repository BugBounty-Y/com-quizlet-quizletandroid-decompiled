package com.facebook.appevents.codeless;

import android.view.View;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements View.OnClickListener {
    public final com.facebook.appevents.codeless.internal.c a;
    public final WeakReference b;
    public final WeakReference c;
    public final View.OnClickListener d;
    public final boolean e;

    public a(com.facebook.appevents.codeless.internal.c mapping, View rootView, View hostView) {
        Intrinsics.checkNotNullParameter(mapping, "mapping");
        Intrinsics.checkNotNullParameter(rootView, "rootView");
        Intrinsics.checkNotNullParameter(hostView, "hostView");
        this.a = mapping;
        this.b = new WeakReference(hostView);
        this.c = new WeakReference(rootView);
        this.d = com.facebook.appevents.codeless.internal.g.e(hostView);
        this.e = true;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(view, "view");
            View.OnClickListener onClickListener = this.d;
            if (onClickListener != null) {
                onClickListener.onClick(view);
            }
            View view2 = (View) this.c.get();
            View view3 = (View) this.b.get();
            if (view2 == null || view3 == null) {
                return;
            }
            com.facebook.appevents.codeless.internal.c cVar = this.a;
            Intrinsics.e(cVar, "null cannot be cast to non-null type com.facebook.appevents.codeless.internal.EventBinding");
            c.c(cVar, view2, view3);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
