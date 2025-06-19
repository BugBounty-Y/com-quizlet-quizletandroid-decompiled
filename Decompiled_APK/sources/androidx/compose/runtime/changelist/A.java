package androidx.compose.runtime.changelist;

import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;

/* loaded from: classes.dex */
public final class A extends J {
    public static final A c;

    static {
        int i = 0;
        c = new A(i, i, 3);
    }

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        if (d0.n != 0) {
            androidx.compose.runtime.r.c("Cannot reset when inserting");
        }
        d0.G();
        d0.t = 0;
        d0.u = d0.m() - d0.h;
        d0.i = 0;
        d0.j = 0;
        d0.o = 0;
    }
}
