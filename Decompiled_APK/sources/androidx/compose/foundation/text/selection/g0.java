package androidx.compose.foundation.text.selection;

import androidx.compose.foundation.text.AbstractC0484d0;
import androidx.compose.foundation.text.K0;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.input.C0998a;
import androidx.compose.ui.text.input.InterfaceC1006i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import java.util.List;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g0 {
    public final C0995g a;
    public final long b;
    public final androidx.compose.ui.text.H c;
    public final androidx.compose.ui.text.input.s d;
    public final o0 e;
    public long f;
    public final C0995g g;
    public final androidx.compose.ui.text.input.A h;
    public final K0 i;

    public g0(androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.s sVar, K0 k0, o0 o0Var) {
        C0995g c0995g = a.a;
        androidx.compose.ui.text.H h = k0 != null ? k0.a : null;
        long j = a.b;
        this.a = c0995g;
        this.b = j;
        this.c = h;
        this.d = sVar;
        this.e = o0Var;
        this.f = j;
        this.g = c0995g;
        this.h = a;
        this.i = k0;
    }

    public final List a(Function1 function1) {
        if (!androidx.compose.ui.text.K.b(this.f)) {
            return kotlin.collections.B.j(new C0998a("", 0), new androidx.compose.ui.text.input.y(androidx.compose.ui.text.K.e(this.f), androidx.compose.ui.text.K.e(this.f)));
        }
        InterfaceC1006i interfaceC1006i = (InterfaceC1006i) function1.invoke(this);
        if (interfaceC1006i != null) {
            return kotlin.collections.A.b(interfaceC1006i);
        }
        return null;
    }

    public final Integer b() {
        androidx.compose.ui.text.H h = this.c;
        if (h == null) {
            return null;
        }
        int iD = androidx.compose.ui.text.K.d(this.f);
        androidx.compose.ui.text.input.s sVar = this.d;
        return Integer.valueOf(sVar.g(h.e(h.f(sVar.p(iD)), true)));
    }

    public final Integer c() {
        int length;
        androidx.compose.ui.text.H h = this.c;
        if (h == null) {
            return null;
        }
        int iP = p();
        while (true) {
            C0995g c0995g = this.a;
            if (iP < c0995g.a.length()) {
                int length2 = this.g.a.length() - 1;
                if (iP <= length2) {
                    length2 = iP;
                }
                long jL = h.l(length2);
                int i = androidx.compose.ui.text.K.c;
                int i2 = (int) (jL & 4294967295L);
                if (i2 > iP) {
                    length = this.d.g(i2);
                    break;
                }
                iP++;
            } else {
                length = c0995g.a.length();
                break;
            }
        }
        return Integer.valueOf(length);
    }

    public final Integer d() {
        int iG;
        androidx.compose.ui.text.H h = this.c;
        if (h == null) {
            return null;
        }
        int iP = p();
        while (true) {
            if (iP <= 0) {
                iG = 0;
                break;
            }
            int length = this.g.a.length() - 1;
            if (iP <= length) {
                length = iP;
            }
            long jL = h.l(length);
            int i = androidx.compose.ui.text.K.c;
            int i2 = (int) (jL >> 32);
            if (i2 < iP) {
                iG = this.d.g(i2);
                break;
            }
            iP--;
        }
        return Integer.valueOf(iG);
    }

    public final boolean e() {
        androidx.compose.ui.text.H h = this.c;
        return (h != null ? h.j(p()) : null) != androidx.compose.ui.text.style.h.b;
    }

    public final int f(androidx.compose.ui.text.H h, int i) {
        int iP = p();
        o0 o0Var = this.e;
        if (o0Var.a == null) {
            o0Var.a = Float.valueOf(h.c(iP).a);
        }
        int iF = h.f(iP) + i;
        if (iF < 0) {
            return 0;
        }
        androidx.compose.ui.text.o oVar = h.b;
        if (iF >= oVar.f) {
            return this.g.a.length();
        }
        float fB = oVar.b(iF) - 1;
        Float f = o0Var.a;
        Intrinsics.d(f);
        float fFloatValue = f.floatValue();
        if ((e() && fFloatValue >= h.h(iF)) || (!e() && fFloatValue <= h.g(iF))) {
            return h.e(iF, true);
        }
        return this.d.g(oVar.e(Q4.c(f.floatValue(), fB)));
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0011  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int g(androidx.compose.foundation.text.K0 r6, int r7) {
        /*
            r5 = this;
            androidx.compose.ui.layout.r r0 = r6.b
            if (r0 == 0) goto L11
            androidx.compose.ui.layout.r r1 = r6.c
            if (r1 == 0) goto Le
            r2 = 1
            androidx.compose.ui.geometry.c r0 = r1.o(r0, r2)
            goto Lf
        Le:
            r0 = 0
        Lf:
            if (r0 != 0) goto L13
        L11:
            androidx.compose.ui.geometry.c r0 = androidx.compose.ui.geometry.c.e
        L13:
            androidx.compose.ui.text.input.A r1 = r5.h
            long r1 = r1.b
            int r3 = androidx.compose.ui.text.K.c
            r3 = 4294967295(0xffffffff, double:2.1219957905E-314)
            long r1 = r1 & r3
            int r1 = (int) r1
            androidx.compose.ui.text.input.s r2 = r5.d
            int r1 = r2.p(r1)
            androidx.compose.ui.text.H r6 = r6.a
            androidx.compose.ui.geometry.c r1 = r6.c(r1)
            float r3 = r0.e()
            float r0 = r0.d()
            long r3 = com.google.android.gms.internal.mlkit_vision_barcode.T4.a(r3, r0)
            float r0 = androidx.compose.ui.geometry.e.b(r3)
            float r7 = (float) r7
            float r0 = r0 * r7
            float r7 = r1.b
            float r0 = r0 + r7
            float r7 = r1.a
            long r0 = com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(r7, r0)
            androidx.compose.ui.text.o r6 = r6.b
            int r6 = r6.e(r0)
            int r6 = r2.g(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.g0.g(androidx.compose.foundation.text.K0, int):int");
    }

    public final void h() {
        C0995g c0995g = this.g;
        o0 o0Var = this.e;
        o0Var.a = null;
        if (c0995g.a.length() > 0) {
            if (e()) {
                o0Var.a = null;
                if (c0995g.a.length() > 0) {
                    String str = c0995g.a;
                    long j = this.f;
                    int i = androidx.compose.ui.text.K.c;
                    int iV = AbstractC0484d0.v((int) (j & 4294967295L), str);
                    if (iV != -1) {
                        o(iV, iV);
                        return;
                    }
                    return;
                }
                return;
            }
            o0Var.a = null;
            if (c0995g.a.length() > 0) {
                String str2 = c0995g.a;
                long j2 = this.f;
                int i2 = androidx.compose.ui.text.K.c;
                int iS = AbstractC0484d0.s((int) (j2 & 4294967295L), str2);
                if (iS != -1) {
                    o(iS, iS);
                }
            }
        }
    }

    public final void i() {
        this.e.a = null;
        C0995g c0995g = this.g;
        if (c0995g.a.length() > 0) {
            int iD = androidx.compose.ui.text.K.d(this.f);
            String str = c0995g.a;
            int iT = AbstractC0484d0.t(iD, str);
            if (iT == androidx.compose.ui.text.K.d(this.f) && iT != str.length()) {
                iT = AbstractC0484d0.t(iT + 1, str);
            }
            o(iT, iT);
        }
    }

    public final void j() {
        this.e.a = null;
        C0995g c0995g = this.g;
        if (c0995g.a.length() > 0) {
            int iE = androidx.compose.ui.text.K.e(this.f);
            String str = c0995g.a;
            int iU = AbstractC0484d0.u(iE, str);
            if (iU == androidx.compose.ui.text.K.e(this.f) && iU != 0) {
                iU = AbstractC0484d0.u(iU - 1, str);
            }
            o(iU, iU);
        }
    }

    public final void k() {
        C0995g c0995g = this.g;
        o0 o0Var = this.e;
        o0Var.a = null;
        if (c0995g.a.length() > 0) {
            if (e()) {
                o0Var.a = null;
                if (c0995g.a.length() > 0) {
                    String str = c0995g.a;
                    long j = this.f;
                    int i = androidx.compose.ui.text.K.c;
                    int iS = AbstractC0484d0.s((int) (j & 4294967295L), str);
                    if (iS != -1) {
                        o(iS, iS);
                        return;
                    }
                    return;
                }
                return;
            }
            o0Var.a = null;
            if (c0995g.a.length() > 0) {
                String str2 = c0995g.a;
                long j2 = this.f;
                int i2 = androidx.compose.ui.text.K.c;
                int iV = AbstractC0484d0.v((int) (j2 & 4294967295L), str2);
                if (iV != -1) {
                    o(iV, iV);
                }
            }
        }
    }

    public final void l() {
        Integer numB;
        this.e.a = null;
        if (this.g.a.length() <= 0 || (numB = b()) == null) {
            return;
        }
        int iIntValue = numB.intValue();
        o(iIntValue, iIntValue);
    }

    public final void m() {
        Integer numValueOf = null;
        this.e.a = null;
        if (this.g.a.length() > 0) {
            androidx.compose.ui.text.H h = this.c;
            if (h != null) {
                int iE = androidx.compose.ui.text.K.e(this.f);
                androidx.compose.ui.text.input.s sVar = this.d;
                numValueOf = Integer.valueOf(sVar.g(h.i(h.f(sVar.p(iE)))));
            }
            if (numValueOf != null) {
                int iIntValue = numValueOf.intValue();
                o(iIntValue, iIntValue);
            }
        }
    }

    public final void n() {
        if (this.g.a.length() > 0) {
            int i = androidx.compose.ui.text.K.c;
            this.f = AbstractC3205m5.c((int) (this.b >> 32), (int) (this.f & 4294967295L));
        }
    }

    public final void o(int i, int i2) {
        this.f = AbstractC3205m5.c(i, i2);
    }

    public final int p() {
        long j = this.f;
        int i = androidx.compose.ui.text.K.c;
        return this.d.p((int) (j & 4294967295L));
    }
}
