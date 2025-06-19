package com.quizlet.assembly.compose.buttons;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;

/* renamed from: com.quizlet.assembly.compose.buttons.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4078c {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;

    public /* synthetic */ C4078c(long j, long j2, long j3, long j4, long j5, int i) {
        this(j, j2, j3, j4, (i & 16) != 0 ? j : j5, j2);
    }

    public static C4078c c(C4078c c4078c, long j, long j2) {
        long j3 = c4078c.c;
        long j4 = c4078c.d;
        long j5 = c4078c.e;
        long j6 = c4078c.f;
        c4078c.getClass();
        return new C4078c(j, j2, j3, j4, j5, j6);
    }

    public final InterfaceC0773a0 a(boolean z, boolean z2, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-781414013);
        InterfaceC0773a0 interfaceC0773a0D = C0776c.D(new C0861v(!z ? this.c : z2 ? this.e : this.a), c0814p);
        c0814p.p(false);
        return interfaceC0773a0D;
    }

    public final InterfaceC0773a0 b(boolean z, boolean z2, InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(631609851);
        InterfaceC0773a0 interfaceC0773a0D = C0776c.D(new C0861v(!z ? this.d : z2 ? this.f : this.b), c0814p);
        c0814p.p(false);
        return interfaceC0773a0D;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4078c)) {
            return false;
        }
        C4078c c4078c = (C4078c) obj;
        return C0861v.c(this.a, c4078c.a) && C0861v.c(this.b, c4078c.b) && C0861v.c(this.c, c4078c.c) && C0861v.c(this.d, c4078c.d) && C0861v.c(this.e, c4078c.e) && C0861v.c(this.f, c4078c.f);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.f) + androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        String strI = C0861v.i(this.a);
        String strI2 = C0861v.i(this.b);
        String strI3 = C0861v.i(this.c);
        String strI4 = C0861v.i(this.d);
        String strI5 = C0861v.i(this.e);
        String strI6 = C0861v.i(this.f);
        StringBuilder sbH = AbstractC0147y.h("AssemblyButtonColors(containerColor=", strI, ", contentColor=", strI2, ", disabledContainerColor=");
        androidx.compose.ui.node.B.u(sbH, strI3, ", disabledContentColor=", strI4, ", pressedContainerColor=");
        return androidx.compose.ui.node.B.j(sbH, strI5, ", pressedContentColor=", strI6, ")");
    }

    public C4078c(long j, long j2, long j3, long j4, long j5, long j6) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
    }
}
