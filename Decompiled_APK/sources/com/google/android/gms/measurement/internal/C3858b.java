package com.google.android.gms.measurement.internal;

import com.google.android.gms.internal.measurement.C2981d3;
import com.google.android.gms.internal.measurement.C3019l1;
import com.google.android.gms.internal.measurement.C3028n0;
import com.google.android.gms.internal.measurement.C3038p0;
import com.google.android.gms.internal.measurement.C3052s0;
import com.google.android.gms.internal.measurement.C3062u0;
import com.google.android.gms.internal.measurement.C3067v0;
import com.google.android.gms.internal.measurement.W1;
import java.math.BigDecimal;

/* renamed from: com.google.android.gms.measurement.internal.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3858b extends androidx.navigation.C {
    public final /* synthetic */ int g;
    public final /* synthetic */ C3860c h;
    public final W1 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C3858b(C3860c c3860c, String str, int i, W1 w1, int i2) {
        super(str, i);
        this.g = i2;
        this.h = c3860c;
        this.i = w1;
    }

    @Override // androidx.navigation.C
    public final int c() {
        switch (this.g) {
            case 0:
                return ((C3028n0) this.i).o();
            default:
                return ((C3062u0) this.i).n();
        }
    }

    @Override // androidx.navigation.C
    public final boolean d() {
        switch (this.g) {
            case 0:
                return ((C3028n0) this.i).z();
            default:
                return false;
        }
    }

    @Override // androidx.navigation.C
    public final boolean e() {
        switch (this.g) {
            case 0:
                return false;
            default:
                return true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:103:0x0292, code lost:
    
        r16 = r3;
        r17 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x02b1, code lost:
    
        r16 = r3;
        r17 = r4;
     */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0178  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean j(java.lang.Long r19, java.lang.Long r20, com.google.android.gms.internal.measurement.U0 r21, long r22, com.google.android.gms.measurement.internal.C3882n r24, boolean r25) {
        /*
            Method dump skipped, instructions count: 1067
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.C3858b.j(java.lang.Long, java.lang.Long, com.google.android.gms.internal.measurement.U0, long, com.google.android.gms.measurement.internal.n, boolean):boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public boolean k(Long l, Long l2, C3019l1 c3019l1, boolean z) {
        C2981d3.a();
        Y y = (Y) this.h.b;
        boolean zF0 = y.g.f0(this.a, AbstractC3893t.C0);
        C3062u0 c3062u0 = (C3062u0) this.i;
        boolean zS = c3062u0.s();
        boolean zT = c3062u0.t();
        boolean zU = c3062u0.u();
        Object[] objArr = zS || zT || zU;
        Boolean boolI = null;
        boolF = null;
        Boolean boolF = null;
        boolI = null;
        boolI = null;
        boolI = null;
        Boolean boolF2 = null;
        boolI = null;
        I i = y.i;
        if (z && objArr != true) {
            Y.k(i);
            i.o.h("Property filter already evaluated true and it is not associated with an enhanced audience. audience ID, filter ID", Integer.valueOf(this.b), c3062u0.v() ? Integer.valueOf(c3062u0.n()) : null);
            return true;
        }
        C3038p0 c3038p0O = c3062u0.o();
        boolean zS2 = c3038p0O.s();
        boolean zE = c3019l1.E();
        D d = y.m;
        if (zE) {
            if (c3038p0O.u()) {
                boolI = androidx.navigation.C.i(androidx.navigation.C.h(c3019l1.p(), c3038p0O.o()), zS2);
            } else {
                Y.k(i);
                i.j.g("No number filter for long property. property", d.f(c3019l1.s()));
            }
        } else if (c3019l1.C()) {
            if (c3038p0O.u()) {
                double dN = c3019l1.n();
                try {
                    boolF = androidx.navigation.C.f(new BigDecimal(dN), c3038p0O.o(), Math.ulp(dN));
                } catch (NumberFormatException unused) {
                }
                boolI = androidx.navigation.C.i(boolF, zS2);
            } else {
                Y.k(i);
                i.j.g("No number filter for double property. property", d.f(c3019l1.s()));
            }
        } else if (!c3019l1.G()) {
            Y.k(i);
            i.j.g("User property has no value, property", d.f(c3019l1.s()));
        } else if (c3038p0O.w()) {
            String strT = c3019l1.t();
            C3067v0 c3067v0P = c3038p0O.p();
            Y.k(i);
            boolI = androidx.navigation.C.i(androidx.navigation.C.g(strT, c3067v0P, i), zS2);
        } else if (!c3038p0O.u()) {
            Y.k(i);
            i.j.g("No string or number filter defined. property", d.f(c3019l1.s()));
        } else if (M.W(c3019l1.t())) {
            String strT2 = c3019l1.t();
            C3052s0 c3052s0O = c3038p0O.o();
            if (M.W(strT2)) {
                try {
                    boolF2 = androidx.navigation.C.f(new BigDecimal(strT2), c3052s0O, 0.0d);
                } catch (NumberFormatException unused2) {
                }
            }
            boolI = androidx.navigation.C.i(boolF2, zS2);
        } else {
            Y.k(i);
            i.j.h("Invalid user property value for Numeric number filter. property, value", d.f(c3019l1.s()), c3019l1.t());
        }
        Y.k(i);
        i.o.g("Property filter result", boolI == null ? "null" : boolI);
        if (boolI == null) {
            return false;
        }
        this.c = Boolean.TRUE;
        if (!zU || boolI.booleanValue()) {
            if (!z || c3062u0.s()) {
                this.d = boolI;
            }
            if (boolI.booleanValue() && objArr != false && c3019l1.F()) {
                long jQ = c3019l1.q();
                if (l != null) {
                    jQ = l.longValue();
                }
                if (zF0 && c3062u0.s() && !c3062u0.t() && l2 != null) {
                    jQ = l2.longValue();
                }
                if (c3062u0.t()) {
                    this.f = Long.valueOf(jQ);
                } else {
                    this.e = Long.valueOf(jQ);
                }
            }
        }
        return true;
    }
}
