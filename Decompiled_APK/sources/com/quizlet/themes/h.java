package com.quizlet.themes;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes3.dex */
public final class h {
    public final long a;
    public final long b;

    public h(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return C0861v.c(this.a, hVar.a) && C0861v.c(this.b, hVar.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return AbstractC0147y.e("ColorScheme(light=", C0861v.i(this.a), ", dark=", C0861v.i(this.b), ")");
    }
}
