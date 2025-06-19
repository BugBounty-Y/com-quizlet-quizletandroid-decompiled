package androidx.compose.foundation.layout;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.layout.InterfaceC0901w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class N extends androidx.compose.ui.platform.N implements InterfaceC0901w, androidx.compose.ui.modifier.c {
    public final C0378c d;
    public final InterfaceC0773a0 e;

    public N(C0378c c0378c) {
        this.d = c0378c;
        this.e = C0776c.z(c0378c);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof N) {
            return Intrinsics.b(this.d, ((N) obj).d);
        }
        return false;
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        int iC = ((R0) ((androidx.compose.runtime.L0) this.e).getValue()).c(m);
        if (iC == 0) {
            return m.n0(0, 0, kotlin.collections.V.c(), C0406q.d);
        }
        androidx.compose.ui.layout.W wB = j.B(androidx.compose.ui.unit.a.a(j2, 0, 0, iC, iC, 3));
        return m.n0(wB.a, iC, kotlin.collections.V.c(), new androidx.compose.animation.C(wB, 4));
    }

    public final int hashCode() {
        return C0396l.c.hashCode() + (this.d.hashCode() * 31);
    }

    @Override // androidx.compose.ui.modifier.c
    public final void j(androidx.compose.ui.modifier.g gVar) {
        ((androidx.compose.runtime.L0) this.e).setValue(new O(this.d, (R0) gVar.d(U0.a)));
    }
}
