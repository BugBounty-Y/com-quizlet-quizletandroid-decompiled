package com.quizlet.quizletandroid.ui.common.views;

import android.graphics.Paint;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final float a;
    public final Paint b;

    public a(float f, Paint paint) {
        Intrinsics.checkNotNullParameter(paint, "paint");
        this.a = f;
        this.b = paint;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Float.compare(this.a, aVar.a) == 0 && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Bucket(size=" + this.a + ", paint=" + this.b + ")";
    }
}
