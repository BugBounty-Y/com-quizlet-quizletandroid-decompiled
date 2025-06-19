package com.google.android.material.textfield;

import android.graphics.RectF;
import android.graphics.drawable.Drawable;

/* loaded from: classes2.dex */
public final class f extends com.google.android.material.shape.f {
    public final RectF s;

    public f(com.google.android.material.shape.j jVar, RectF rectF) {
        super(jVar);
        this.s = rectF;
    }

    @Override // com.google.android.material.shape.f, android.graphics.drawable.Drawable.ConstantState
    public final Drawable newDrawable() {
        g gVar = new g(this);
        gVar.y = this;
        gVar.invalidateSelf();
        return gVar;
    }

    public f(f fVar) {
        super(fVar);
        this.s = fVar.s;
    }
}
