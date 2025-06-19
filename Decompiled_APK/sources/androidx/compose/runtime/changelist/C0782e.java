package androidx.compose.runtime.changelist;

import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.C0836x0;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;

/* renamed from: androidx.compose.runtime.changelist.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0782e extends J {
    public static final C0782e c = new C0782e(0, 2, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        C0774b c0774b = (C0774b) k.f(0);
        Object objF = k.f(1);
        if (objF instanceof C0836x0) {
            ((androidx.compose.runtime.collection.b) jVar.c).b((C0836x0) objF);
        }
        if (d0.n != 0) {
            androidx.compose.runtime.r.c("Can only append a slot if not current inserting");
        }
        int i = d0.i;
        int i2 = d0.j;
        int iC = d0.c(c0774b);
        int iF = d0.f(d0.b, d0.q(iC + 1));
        d0.i = iF;
        d0.j = iF;
        d0.v(1, iC);
        if (i >= iF) {
            i++;
            i2++;
        }
        d0.c[iF] = objF;
        d0.i = i;
        d0.j = i2;
    }
}
