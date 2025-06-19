package androidx.compose.runtime.changelist;

import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.D0;
import androidx.compose.runtime.InterfaceC0790d;
import androidx.compose.runtime.Y;
import androidx.compose.runtime.Z;
import java.util.List;
import kotlin.KotlinNothingValueException;

/* renamed from: androidx.compose.runtime.changelist.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0785h extends J {
    public static final C0785h c = new C0785h(0, 4, 1);

    @Override // androidx.compose.runtime.changelist.J
    public final void a(K k, InterfaceC0790d interfaceC0790d, D0 d0, androidx.compose.runtime.internal.j jVar) {
        Z z = (Z) k.f(2);
        Z z2 = (Z) k.f(3);
        AbstractC0827t abstractC0827t = (AbstractC0827t) k.f(1);
        Y yM = (Y) k.f(0);
        if (yM == null && (yM = abstractC0827t.m(z)) == null) {
            androidx.compose.runtime.r.d("Could not resolve state for movable content");
            throw new KotlinNothingValueException();
        }
        if (d0.n > 0 || d0.s(d0.t + 1) != 1) {
            androidx.compose.runtime.r.c("Check failed");
        }
        int i = d0.t;
        int i2 = d0.i;
        int i3 = d0.j;
        d0.a(1);
        d0.P();
        d0.d();
        D0 d0G = yM.a.g();
        try {
            List listU = C0776c.u(d0G, 2, d0, false, true, true);
            d0G.e(true);
            d0.j();
            d0.i();
            d0.t = i;
            d0.i = i2;
            d0.j = i3;
            C0776c.k(d0, listU, z2.c);
        } catch (Throwable th) {
            d0G.e(false);
            throw th;
        }
    }
}
