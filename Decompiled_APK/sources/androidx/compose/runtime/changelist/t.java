package androidx.compose.runtime.changelist;

import androidx.compose.runtime.A0;
import androidx.compose.runtime.C0774b;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class t extends J {
    public static final t c = new t(0, 3, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        A0 a0 = (A0) k.f(1);
        C0774b c0774b = (C0774b) k.f(0);
        C0780c c0780c = (C0780c) k.f(2);
        D0 d0G = a0.g();
        try {
            if (!c0780c.c.d()) {
                androidx.compose.runtime.r.c("FixupList has pending fixup operations that were not realized. Were there mismatched insertNode() and endNodeInsert() calls?");
            }
            c0780c.b.c(interfaceC0790d, d0G, jVar);
            Unit unit = Unit.a;
            d0G.e(true);
            d0.d();
            c0774b.getClass();
            d0.y(a0, a0.a(c0774b));
            d0.j();
        } catch (Throwable th) {
            d0G.e(false);
            throw th;
        }
    }
}
