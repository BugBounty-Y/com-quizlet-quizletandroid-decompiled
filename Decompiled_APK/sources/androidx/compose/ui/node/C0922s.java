package androidx.compose.ui.node;

import androidx.compose.ui.layout.C0893n;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.node.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0922s extends P {
    @Override // androidx.compose.ui.layout.J
    public final androidx.compose.ui.layout.W B(long j) {
        x0(j);
        a0 a0Var = this.l;
        androidx.compose.runtime.collection.b bVarW = a0Var.l.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                J j2 = ((E) objArr[i2]).x.s;
                Intrinsics.d(j2);
                j2.i = 3;
                i2++;
            } while (i2 < i);
        }
        E e = a0Var.l;
        P.K0(this, e.p.mo1measure3p2s80s(this, e.l(), j));
        return this;
    }

    @Override // androidx.compose.ui.node.P
    public final void L0() {
        J j = this.l.l.x.s;
        Intrinsics.d(j);
        j.D0();
    }

    @Override // androidx.compose.ui.layout.J
    public final int X(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.minIntrinsicHeight((a0) e.w.d, e.l(), i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int b(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.maxIntrinsicHeight((a0) e.w.d, e.l(), i);
    }

    @Override // androidx.compose.ui.layout.J
    public final int x(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.minIntrinsicWidth((a0) e.w.d, e.l(), i);
    }

    @Override // androidx.compose.ui.node.O
    public final int y0(C0893n c0893n) {
        J j = this.l.l.x.s;
        Intrinsics.d(j);
        boolean z = j.j;
        F f = j.r;
        if (!z) {
            L l = j.y;
            if (l.c == 2) {
                f.f = true;
                if (f.b) {
                    l.h = true;
                    l.i = true;
                }
            } else {
                f.g = true;
            }
        }
        C0922s c0922s = j.e().L;
        if (c0922s != null) {
            c0922s.h = true;
        }
        j.L();
        C0922s c0922s2 = j.e().L;
        if (c0922s2 != null) {
            c0922s2.h = false;
        }
        Integer num = (Integer) f.i.get(c0893n);
        int iIntValue = num != null ? num.intValue() : Integer.MIN_VALUE;
        this.q.put(c0893n, Integer.valueOf(iIntValue));
        return iIntValue;
    }

    @Override // androidx.compose.ui.layout.J
    public final int z(int i) {
        androidx.compose.foundation.text.input.internal.u uVarR = this.l.l.r();
        androidx.compose.ui.layout.K kJ = uVarR.j();
        E e = (E) uVarR.b;
        return kJ.maxIntrinsicWidth((a0) e.w.d, e.l(), i);
    }
}
