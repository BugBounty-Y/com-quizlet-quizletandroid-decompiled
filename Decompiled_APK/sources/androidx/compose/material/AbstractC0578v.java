package androidx.compose.material;

import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.X0;
import androidx.compose.ui.graphics.C0861v;

/* renamed from: androidx.compose.material.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0578v {
    public static final X0 a = new X0(C0577u.b);

    public static final long a(long j, InterfaceC0806l interfaceC0806l) {
        long j2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-702388415);
        C0576t c0576t = (C0576t) c0814p.j(a);
        boolean zC = C0861v.c(j, ((C0861v) ((L0) c0576t.a).getValue()).a);
        InterfaceC0773a0 interfaceC0773a0 = c0576t.h;
        if (zC || C0861v.c(j, ((C0861v) ((L0) c0576t.b).getValue()).a)) {
            j2 = ((C0861v) ((L0) interfaceC0773a0).getValue()).a;
        } else {
            boolean zC2 = C0861v.c(j, ((C0861v) ((L0) c0576t.c).getValue()).a);
            InterfaceC0773a0 interfaceC0773a02 = c0576t.i;
            j2 = (zC2 || C0861v.c(j, ((C0861v) ((L0) c0576t.d).getValue()).a)) ? ((C0861v) ((L0) interfaceC0773a02).getValue()).a : C0861v.c(j, ((C0861v) ((L0) c0576t.e).getValue()).a) ? ((C0861v) ((L0) c0576t.j).getValue()).a : C0861v.c(j, c0576t.a()) ? ((C0861v) ((L0) c0576t.k).getValue()).a : C0861v.c(j, ((C0861v) ((L0) c0576t.g).getValue()).a) ? ((C0861v) ((L0) c0576t.l).getValue()).a : C0861v.g;
        }
        if (j2 == 16) {
            j2 = ((C0861v) c0814p.j(AbstractC0579w.a)).a;
        }
        c0814p.p(false);
        return j2;
    }
}
