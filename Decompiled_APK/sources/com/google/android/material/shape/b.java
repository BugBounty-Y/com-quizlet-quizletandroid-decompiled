package com.google.android.material.shape;

import android.graphics.RectF;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class b implements c {
    public final c a;
    public final float b;

    public b(float f, c cVar) {
        while (cVar instanceof b) {
            cVar = ((b) cVar).a;
            f += ((b) cVar).b;
        }
        this.a = cVar;
        this.b = f;
    }

    @Override // com.google.android.material.shape.c
    public final float a(RectF rectF) {
        return Math.max(DefinitionKt.NO_Float_VALUE, this.a.a(rectF) + this.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b == bVar.b;
    }

    public final int hashCode() {
        return Arrays.hashCode(new Object[]{this.a, Float.valueOf(this.b)});
    }
}
