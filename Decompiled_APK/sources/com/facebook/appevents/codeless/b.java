package com.facebook.appevents.codeless;

import android.view.View;
import android.widget.AdapterView;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements AdapterView.OnItemClickListener {
    public final com.facebook.appevents.codeless.internal.c a;
    public final WeakReference b;
    public final WeakReference c;
    public final AdapterView.OnItemClickListener d;
    public final boolean e;

    public b(com.facebook.appevents.codeless.internal.c mapping, View rootView, AdapterView hostView) {
        Intrinsics.checkNotNullParameter(mapping, "mapping");
        Intrinsics.checkNotNullParameter(rootView, "rootView");
        Intrinsics.checkNotNullParameter(hostView, "hostView");
        this.a = mapping;
        this.b = new WeakReference(hostView);
        this.c = new WeakReference(rootView);
        this.d = hostView.getOnItemClickListener();
        this.e = true;
    }

    @Override // android.widget.AdapterView.OnItemClickListener
    public final void onItemClick(AdapterView adapterView, View view, int i, long j) {
        Intrinsics.checkNotNullParameter(view, "view");
        AdapterView.OnItemClickListener onItemClickListener = this.d;
        if (onItemClickListener != null) {
            onItemClickListener.onItemClick(adapterView, view, i, j);
        }
        View view2 = (View) this.c.get();
        AdapterView adapterView2 = (AdapterView) this.b.get();
        if (view2 == null || adapterView2 == null) {
            return;
        }
        c.c(this.a, view2, adapterView2);
    }
}
