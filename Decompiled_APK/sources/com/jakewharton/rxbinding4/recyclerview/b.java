package com.jakewharton.rxbinding4.recyclerview;

import android.view.View;
import androidx.recyclerview.widget.InterfaceC1385p0;
import androidx.recyclerview.widget.RecyclerView;
import io.reactivex.rxjava3.core.l;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends io.reactivex.rxjava3.android.a implements InterfaceC1385p0 {
    public final RecyclerView b;
    public final l c;

    public b(RecyclerView recyclerView, l observer) {
        Intrinsics.f(observer, "observer");
        this.b = recyclerView;
        this.c = observer;
    }

    @Override // io.reactivex.rxjava3.android.a
    public final void a() {
        ArrayList arrayList = this.b.C;
        if (arrayList == null) {
            return;
        }
        arrayList.remove(this);
    }

    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void b(View childView) {
        Intrinsics.f(childView, "childView");
        if (this.a.get()) {
            return;
        }
        this.c.b(new d(this.b, childView));
    }

    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void c(View childView) {
        Intrinsics.f(childView, "childView");
        if (this.a.get()) {
            return;
        }
        this.c.b(new a(this.b, childView));
    }
}
