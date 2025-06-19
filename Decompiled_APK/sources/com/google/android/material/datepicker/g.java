package com.google.android.material.datepicker;

import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class g extends LinearLayoutManager {
    public final /* synthetic */ int E;
    public final /* synthetic */ k F;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(k kVar, int i, int i2) {
        super(i);
        this.F = kVar;
        this.E = i2;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void F0(RecyclerView recyclerView, B0 b0, int i) {
        t tVar = new t(recyclerView.getContext());
        tVar.a = i;
        G0(tVar);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager
    public final void I0(B0 b0, int[] iArr) {
        int i = this.E;
        k kVar = this.F;
        if (i == 0) {
            iArr[0] = kVar.h.getWidth();
            iArr[1] = kVar.h.getWidth();
        } else {
            iArr[0] = kVar.h.getHeight();
            iArr[1] = kVar.h.getHeight();
        }
    }
}
