package com.jakewharton.rxbinding4.recyclerview;

import androidx.recyclerview.widget.RecyclerView;
import io.reactivex.rxjava3.core.l;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends io.reactivex.rxjava3.android.a {
    public final e b;
    public final RecyclerView c;

    public f(RecyclerView recyclerView, l observer) {
        Intrinsics.f(recyclerView, "recyclerView");
        Intrinsics.f(observer, "observer");
        this.c = recyclerView;
        this.b = new e(this, observer);
    }

    @Override // io.reactivex.rxjava3.android.a
    public final void a() {
        ArrayList arrayList = this.c.t1;
        if (arrayList != null) {
            arrayList.remove(this.b);
        }
    }
}
