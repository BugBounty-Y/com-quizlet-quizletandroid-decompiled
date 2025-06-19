package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.io.EOFException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Iw implements SF {
    public Object a;
    public Object b;
    public Object c;

    public /* synthetic */ Iw() {
        this.b = null;
        this.c = null;
        this.a = C2332lw.r;
    }

    @Override // com.google.android.gms.internal.ads.SF
    public Bu a(int i, J9 j9, int[] iArr) {
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i2 = 0;
        int i3 = 0;
        while (i2 < j9.a) {
            int i4 = i;
            J9 j92 = j9;
            RF rf = new RF(i4, j92, i2, (PF) this.c, iArr[i2], (String) this.a, (String) this.b);
            int length = objArrCopyOf.length;
            int i5 = i3 + 1;
            int iH = AbstractC2027eu.h(length, i5);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i3] = rf;
            i2++;
            i3 = i5;
            i = i4;
            j9 = j92;
        }
        return AbstractC2330lu.m(i3, objArrCopyOf);
    }

    public void b(int i) throws InvalidAlgorithmParameterException {
        if (i != 16 && i != 32) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 128-bit and 256-bit AES keys are supported", Integer.valueOf(i * 8)));
        }
        this.b = Integer.valueOf(i);
    }

    public long c() {
        P p = (P) this.b;
        if (p != null) {
            return p.d;
        }
        return -1L;
    }

    public void d(int i) throws GeneralSecurityException {
        if (i < 10 || i > 16) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.f(i, "Invalid tag size for AesCmacParameters: "));
        }
        this.c = Integer.valueOf(i);
    }

    public Jw e() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAB;
        Mw mw = (Mw) this.c;
        if (mw == null || (c2883yp = (C2883yp) this.a) == null) {
            throw new GeneralSecurityException("Cannot build without parameters and/or key material");
        }
        if (mw.a != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        if (mw.a() && ((Integer) this.b) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((Mw) this.c).a() && ((Integer) this.b) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        Lw lw = ((Mw) this.c).c;
        if (lw == Lw.e) {
            c2604sAB = Yx.a;
        } else if (lw == Lw.d) {
            c2604sAB = Yx.a(((Integer) this.b).intValue());
        } else {
            if (lw != Lw.c) {
                throw new IllegalStateException("Unknown AesEaxParameters.Variant: ".concat(String.valueOf(((Mw) this.c).c)));
            }
            c2604sAB = Yx.b(((Integer) this.b).intValue());
        }
        return new Jw((Mw) this.c, (C2883yp) this.a, c2604sAB, (Integer) this.b);
    }

    public Nw f() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAB;
        Pw pw = (Pw) this.c;
        if (pw == null || (c2883yp = (C2883yp) this.a) == null) {
            throw new GeneralSecurityException("Cannot build without parameters and/or key material");
        }
        if (pw.a != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        if (pw.a() && ((Integer) this.b) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((Pw) this.c).a() && ((Integer) this.b) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        C2332lw c2332lw = ((Pw) this.c).b;
        if (c2332lw == C2332lw.h) {
            c2604sAB = Yx.a;
        } else if (c2332lw == C2332lw.g) {
            c2604sAB = Yx.a(((Integer) this.b).intValue());
        } else {
            if (c2332lw != C2332lw.f) {
                throw new IllegalStateException("Unknown AesGcmParameters.Variant: ".concat(String.valueOf(((Pw) this.c).b)));
            }
            c2604sAB = Yx.b(((Integer) this.b).intValue());
        }
        return new Nw((Pw) this.c, (C2883yp) this.a, c2604sAB, (Integer) this.b);
    }

    public Qw g() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAB;
        Sw sw = (Sw) this.c;
        if (sw == null || (c2883yp = (C2883yp) this.a) == null) {
            throw new GeneralSecurityException("Cannot build without parameters and/or key material");
        }
        if (sw.a != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        if (sw.a() && ((Integer) this.b) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((Sw) this.c).a() && ((Integer) this.b) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        Ew ew = ((Sw) this.c).b;
        if (ew == Ew.j) {
            c2604sAB = Yx.a;
        } else if (ew == Ew.i) {
            c2604sAB = Yx.a(((Integer) this.b).intValue());
        } else {
            if (ew != Ew.h) {
                throw new IllegalStateException("Unknown AesGcmSivParameters.Variant: ".concat(String.valueOf(((Sw) this.c).b)));
            }
            c2604sAB = Yx.b(((Integer) this.b).intValue());
        }
        return new Qw((Sw) this.c, (C2883yp) this.a, c2604sAB, (Integer) this.b);
    }

    public C2720uy h() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAA;
        C2892yy c2892yy = (C2892yy) this.c;
        if (c2892yy == null || (c2883yp = (C2883yp) this.a) == null) {
            throw new GeneralSecurityException("Cannot build without parameters and/or key material");
        }
        if (c2892yy.a != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        if (c2892yy.a() && ((Integer) this.b) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((C2892yy) this.c).a() && ((Integer) this.b) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        C2332lw c2332lw = ((C2892yy) this.c).c;
        if (c2332lw == C2332lw.r) {
            c2604sAA = Yx.a;
        } else if (c2332lw == C2332lw.q || c2332lw == C2332lw.p) {
            c2604sAA = Yx.a(((Integer) this.b).intValue());
        } else {
            if (c2332lw != C2332lw.o) {
                throw new IllegalStateException("Unknown AesCmacParametersParameters.Variant: ".concat(String.valueOf(((C2892yy) this.c).c)));
            }
            c2604sAA = Yx.b(((Integer) this.b).intValue());
        }
        return new C2720uy((C2892yy) this.c, (C2883yp) this.a, c2604sAA, (Integer) this.b);
    }

    public C2892yy i() throws GeneralSecurityException {
        Integer num = (Integer) this.b;
        if (num == null) {
            throw new GeneralSecurityException("key size not set");
        }
        if (((Integer) this.c) != null) {
            return new C2892yy(num.intValue(), ((Integer) this.c).intValue(), (C2332lw) this.a);
        }
        throw new GeneralSecurityException("tag size not set");
    }

    public Ay j() throws GeneralSecurityException {
        C2883yp c2883yp;
        C2604sA c2604sAA;
        Ey ey = (Ey) this.c;
        if (ey == null || (c2883yp = (C2883yp) this.a) == null) {
            throw new GeneralSecurityException("Cannot build without parameters and/or key material");
        }
        if (ey.a != ((C2604sA) c2883yp.b).a.length) {
            throw new GeneralSecurityException("Key size mismatch");
        }
        if (ey.a() && ((Integer) this.b) == null) {
            throw new GeneralSecurityException("Cannot create key without ID requirement with parameters with ID requirement");
        }
        if (!((Ey) this.c).a() && ((Integer) this.b) != null) {
            throw new GeneralSecurityException("Cannot create key with ID requirement with parameters without ID requirement");
        }
        Dy dy = ((Ey) this.c).c;
        if (dy == Dy.e) {
            c2604sAA = Yx.a;
        } else if (dy == Dy.d || dy == Dy.c) {
            c2604sAA = Yx.a(((Integer) this.b).intValue());
        } else {
            if (dy != Dy.b) {
                throw new IllegalStateException("Unknown HmacParameters.Variant: ".concat(String.valueOf(((Ey) this.c).c)));
            }
            c2604sAA = Yx.b(((Integer) this.b).intValue());
        }
        return new Ay((Ey) this.c, (C2883yp) this.a, c2604sAA, (Integer) this.b);
    }

    public void k(Fw fw, Uri uri, Map map, long j, long j2, C2695uF c2695uF) throws zzxf {
        boolean z;
        boolean z2 = true;
        P p = new P(fw, j, j2);
        this.b = p;
        if (((U) this.a) != null) {
            return;
        }
        U[] uArrA = ((X) this.c).a(uri, map);
        int length = uArrA.length;
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(length, "expectedSize");
        C2159hu c2159hu = new C2159hu(length);
        if (length == 1) {
            this.a = uArrA[0];
        } else {
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                U u = uArrA[i];
                try {
                } catch (EOFException unused) {
                    z = ((U) this.a) != null || p.d == j;
                } catch (Throwable th) {
                    if (((U) this.a) == null && p.d != j) {
                        z2 = false;
                    }
                    AbstractC1795We.L(z2);
                    p.f = 0;
                    throw th;
                }
                if (u.d(p)) {
                    this.a = u;
                    p.f = 0;
                    break;
                } else {
                    c2159hu.f(u.j());
                    z = ((U) this.a) != null || p.d == j;
                    AbstractC1795We.L(z);
                    p.f = 0;
                    i++;
                }
            }
            if (((U) this.a) == null) {
                Iterator it2 = AbstractC1981ds.n(AbstractC2330lu.o(uArrA), new C2853y1(20)).iterator();
                StringBuilder sb = new StringBuilder();
                AbstractC2025es.u(sb, it2, ", ");
                String strB = android.support.v4.media.session.a.B("None of the available extractors (", sb.toString(), ") could read the stream.");
                Bu buJ = c2159hu.j();
                zzxf zzxfVar = new zzxf(strB, null, false, 1);
                AbstractC2330lu.n(buJ);
                throw zzxfVar;
            }
        }
        ((U) this.a).e(c2695uF);
    }

    public /* synthetic */ Iw(boolean z) {
        this.c = null;
        this.a = null;
        this.b = null;
    }
}
