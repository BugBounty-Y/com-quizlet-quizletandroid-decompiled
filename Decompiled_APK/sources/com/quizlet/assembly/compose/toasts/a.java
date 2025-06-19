package com.quizlet.assembly.compose.toasts;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes2.dex */
public final class a {
    public final long a;
    public final long b;

    public a(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return C0861v.c(this.a, aVar.a) && C0861v.c(this.b, aVar.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return AbstractC0147y.e("AssemblyToastColors(containerColor=", C0861v.i(this.a), ", contentColor=", C0861v.i(this.b), ")");
    }
}
