package com.google.android.gms.measurement.internal;

import java.math.BigInteger;
import java.util.List;
import java.util.Locale;

/* loaded from: classes2.dex */
public final class A extends AbstractC3888q {
    public String d;
    public String e;
    public int f;
    public String g;
    public String h;
    public long i;
    public final long j;
    public final long k;
    public List l;
    public String m;
    public int n;
    public String o;
    public String p;
    public String q;
    public long r;
    public String s;

    public A(Y y, long j, long j2) {
        super(y);
        this.r = 0L;
        this.s = null;
        this.j = j;
        this.k = j2;
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:109:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x02c2  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x02cf  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x02f0  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0303  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x025b A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x018e  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01c0  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01c2  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x01d7  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01f2  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01f7  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x0239  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x023b  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0256  */
    /* JADX WARN: Unreachable blocks removed: 1, instructions: 1 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.zzr V(java.lang.String r51) throws java.lang.IllegalAccessException, java.security.NoSuchAlgorithmException, java.lang.ClassNotFoundException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            Method dump skipped, instructions count: 856
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.A.V(java.lang.String):com.google.android.gms.measurement.internal.zzr");
    }

    public final String W() {
        Q();
        if (((Y) this.b).g.f0(null, AbstractC3893t.p1)) {
            return null;
        }
        return this.p;
    }

    public final String X() {
        Q();
        com.google.android.gms.common.internal.u.h(this.d);
        return this.d;
    }

    public final String Y() {
        S();
        Q();
        com.google.android.gms.common.internal.u.h(this.o);
        return this.o;
    }

    public final void Z() {
        String str;
        S();
        Y y = (Y) this.b;
        O o = y.h;
        Y.h(o);
        boolean zK = o.Z().k(EnumC3879l0.ANALYTICS_STORAGE);
        I i = y.i;
        if (zK) {
            byte[] bArr = new byte[16];
            x1 x1Var = y.l;
            Y.h(x1Var);
            x1Var.d0().nextBytes(bArr);
            str = String.format(Locale.US, "%032x", new BigInteger(1, bArr));
        } else {
            Y.k(i);
            i.n.f("Analytics Storage consent is not granted");
            str = null;
        }
        Y.k(i);
        i.n.f("Resetting session stitching token to ".concat(str == null ? "null" : "not null"));
        this.q = str;
        y.n.getClass();
        this.r = System.currentTimeMillis();
    }
}
