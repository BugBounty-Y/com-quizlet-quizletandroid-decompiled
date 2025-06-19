package com.jakewharton.rxbinding4.recyclerview;

import androidx.recyclerview.widget.AbstractC1390s0;
import androidx.recyclerview.widget.RecyclerView;
import io.reactivex.rxjava3.core.l;

/* loaded from: classes2.dex */
public final class e extends AbstractC1390s0 {
    public final /* synthetic */ f a;
    public final /* synthetic */ l b;

    public e(f fVar, l lVar) {
        this.a = fVar;
        this.b = lVar;
    }

    @Override // androidx.recyclerview.widget.AbstractC1390s0
    public final void a(RecyclerView recyclerView, int i) {
        if (this.a.a.get()) {
            return;
        }
        this.b.b(Integer.valueOf(i));
    }
}
