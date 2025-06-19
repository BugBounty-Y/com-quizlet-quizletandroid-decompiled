package com.google.android.material.resources;

import android.graphics.Typeface;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;

/* loaded from: classes2.dex */
public final class b extends AbstractC3448e4 {
    public final Typeface a;
    public final a b;
    public boolean c;

    public b(a aVar, Typeface typeface) {
        this.a = typeface;
        this.b = aVar;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void e(int i) {
        if (this.c) {
            return;
        }
        this.b.l(this.a);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void f(Typeface typeface, boolean z) {
        if (this.c) {
            return;
        }
        this.b.l(typeface);
    }
}
