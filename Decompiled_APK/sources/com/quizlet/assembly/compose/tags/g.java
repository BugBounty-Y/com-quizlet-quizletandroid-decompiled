package com.quizlet.assembly.compose.tags;

import androidx.compose.foundation.layout.A0;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.themes.m;
import com.quizlet.ui.compose.C4832z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class g {
    public static final float a;
    public static final float b;

    static {
        m mVar = m.g;
        a = m.d0;
        mVar.h();
        b = com.quizlet.ui.resources.designsystem.generated.h.g;
    }

    public static C4832z a(long j, long j2, long j3, long j4, long j5, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1353854609);
        B b2 = com.quizlet.themes.g.a;
        C4832z c4832z = new C4832z(((com.quizlet.themes.b) c0814p.j(b2)).P, (i & 2) != 0 ? ((com.quizlet.themes.b) c0814p.j(b2)).b.f() : j, (i & 4) != 0 ? ((com.quizlet.themes.b) c0814p.j(b2)).b.f() : j2, (i & 8) != 0 ? ((com.quizlet.themes.b) c0814p.j(b2)).Q : j3, (i & 16) != 0 ? ((com.quizlet.themes.b) c0814p.j(b2)).e : j4, (i & 32) != 0 ? ((com.quizlet.themes.b) c0814p.j(b2)).e : j5, ((com.quizlet.themes.b) c0814p.j(b2)).P, ((com.quizlet.themes.b) c0814p.j(b2)).b.b(), ((com.quizlet.themes.b) c0814p.j(b2)).b.b());
        c0814p.p(false);
        return c4832z;
    }

    public static float b(j size) {
        Intrinsics.checkNotNullParameter(size, "size");
        int iOrdinal = size.ordinal();
        if (iOrdinal == 0) {
            return e.a;
        }
        if (iOrdinal == 1) {
            return e.b;
        }
        if (iOrdinal == 2) {
            return e.c;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static A0 c(j size) {
        Intrinsics.checkNotNullParameter(size, "size");
        int iOrdinal = size.ordinal();
        if (iOrdinal == 0) {
            return f.a;
        }
        if (iOrdinal == 1) {
            return f.b;
        }
        if (iOrdinal == 2) {
            return f.c;
        }
        throw new NoWhenBranchMatchedException();
    }
}
