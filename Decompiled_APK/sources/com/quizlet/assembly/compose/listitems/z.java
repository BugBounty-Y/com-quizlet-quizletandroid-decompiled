package com.quizlet.assembly.compose.listitems;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.B;
import kotlin.C;
import kotlin.D;

/* loaded from: classes2.dex */
public final class z {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final long h;

    public z(long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
        this.g = j7;
        this.h = j8;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return C0861v.c(this.a, zVar.a) && C0861v.c(this.b, zVar.b) && C0861v.c(this.c, zVar.c) && C0861v.c(this.d, zVar.d) && C0861v.c(this.e, zVar.e) && C0861v.c(this.f, zVar.f) && C0861v.c(this.g, zVar.g) && C0861v.c(this.h, zVar.h);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.h) + d0.d(d0.d(d0.d(d0.d(d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g);
    }

    public final String toString() {
        String strI = C0861v.i(this.a);
        String strI2 = C0861v.i(this.b);
        String strI3 = C0861v.i(this.c);
        String strI4 = C0861v.i(this.d);
        String strI5 = C0861v.i(this.e);
        String strI6 = C0861v.i(this.f);
        String strI7 = C0861v.i(this.g);
        String strI8 = C0861v.i(this.h);
        StringBuilder sbH = AbstractC0147y.h("ContentListItemColors(containerColor=", strI, ", titleContentColor=", strI2, ", metadataContentColor=");
        B.u(sbH, strI3, ", actionColor=", strI4, ", disabledContainerColor=");
        B.u(sbH, strI5, ", disabledTitleContentColor=", strI6, ", disabledMetadataContentColor=");
        return B.j(sbH, strI7, ", disabledActionColor=", strI8, ")");
    }
}
