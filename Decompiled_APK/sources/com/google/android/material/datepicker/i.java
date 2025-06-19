package com.google.android.material.datepicker;

import android.graphics.Canvas;
import androidx.recyclerview.widget.AbstractC1375k0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class i extends AbstractC1375k0 {
    public final /* synthetic */ k a;

    public i(k kVar) {
        this.a = kVar;
        v.c(null);
        v.c(null);
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void onDraw(Canvas canvas, RecyclerView recyclerView, B0 b0) {
        if ((recyclerView.getAdapter() instanceof x) && (recyclerView.getLayoutManager() instanceof GridLayoutManager)) {
            this.a.getClass();
            throw null;
        }
    }
}
