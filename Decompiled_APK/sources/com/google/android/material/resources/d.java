package com.google.android.material.resources;

import android.content.Context;
import android.graphics.Typeface;
import android.text.TextPaint;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4;

/* loaded from: classes2.dex */
public final class d extends AbstractC3448e4 {
    public final /* synthetic */ Context a;
    public final /* synthetic */ TextPaint b;
    public final /* synthetic */ AbstractC3448e4 c;
    public final /* synthetic */ e d;

    public d(e eVar, Context context, TextPaint textPaint, AbstractC3448e4 abstractC3448e4) {
        this.d = eVar;
        this.a = context;
        this.b = textPaint;
        this.c = abstractC3448e4;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void e(int i) {
        this.c.e(i);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_common.AbstractC3448e4
    public final void f(Typeface typeface, boolean z) {
        this.d.g(this.a, this.b, typeface);
        this.c.f(typeface, z);
    }
}
