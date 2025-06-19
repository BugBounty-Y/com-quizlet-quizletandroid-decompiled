package com.google.android.material.resources;

import android.graphics.Typeface;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;

/* loaded from: classes2.dex */
public final class c extends androidx.core.content.res.b {
    public final /* synthetic */ AbstractC3448e4 h;
    public final /* synthetic */ e i;

    public c(e eVar, AbstractC3448e4 abstractC3448e4) {
        this.i = eVar;
        this.h = abstractC3448e4;
    }

    @Override // androidx.core.content.res.b
    public final void i(int i) {
        this.i.m = true;
        this.h.e(i);
    }

    @Override // androidx.core.content.res.b
    public final void j(Typeface typeface) {
        e eVar = this.i;
        eVar.n = Typeface.create(typeface, eVar.c);
        eVar.m = true;
        this.h.f(eVar.n, false);
    }
}
