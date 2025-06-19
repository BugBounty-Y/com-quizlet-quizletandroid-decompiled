package com.quizlet.assembly.compose.tabs;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0555x;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.quizlet.assembly.compose.tags.j;
import com.quizlet.themes.g;
import com.quizlet.themes.m;
import com.quizlet.ui.compose.C4832z;
import com.quizlet.ui.resources.designsystem.generated.h;

/* loaded from: classes2.dex */
public abstract class b {
    public static final float a;
    public static final j b;

    static {
        m.g.i();
        a = h.f;
        b = j.a;
    }

    public static C4832z a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(610952163);
        B b2 = g.a;
        long j = ((com.quizlet.themes.b) c0814p.j(b2)).N;
        long jG = ((com.quizlet.themes.b) c0814p.j(b2)).b.g();
        long j2 = ((com.quizlet.themes.b) c0814p.j(b2)).O;
        C4832z c4832zA = com.quizlet.assembly.compose.tags.g.a(j, j, jG, j2, j2, c0814p, 449);
        c0814p.p(false);
        return c4832zA;
    }

    public static C0555x b(boolean z, InterfaceC0806l interfaceC0806l) {
        C0555x c0555xA;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1999967947);
        if (z) {
            c0555xA = AbstractC0460p.a(((com.quizlet.themes.b) c0814p.j(g.a)).b.f(), m.i);
        } else {
            c0555xA = null;
        }
        c0814p.p(false);
        return c0555xA;
    }
}
