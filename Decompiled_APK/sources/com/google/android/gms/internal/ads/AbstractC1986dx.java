package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.dx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1986dx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey");
        a = new C1944cy(C1943cx.class, new Is(24));
        b = new Zx(c2604sAB, new Is(25));
        c = new Ix(C1900bx.class, new Is(26));
        d = new Gx(c2604sAB, new Is(27));
    }

    public static C1943cx a(Xz xz, Yz yz) throws GeneralSecurityException {
        C2332lw c2332lw;
        Fz fzW = Gz.w();
        fzW.h(xz.w().B());
        fzW.i(xz.w().A());
        fzW.g(Yz.RAW);
        AbstractC2547qw abstractC2547qwG = AbstractC2457os.g(((Gz) fzW.c()).d());
        boolean z = abstractC2547qwG instanceof Pw;
        Object obj = C2332lw.n;
        C2332lw c2332lw2 = C2332lw.m;
        C2332lw c2332lw3 = C2332lw.l;
        C2332lw c2332lw4 = C2332lw.j;
        C2332lw c2332lw5 = C2332lw.k;
        C2332lw c2332lw6 = C2332lw.i;
        if (z) {
            c2332lw = c2332lw6;
        } else if (abstractC2547qwG instanceof Vw) {
            c2332lw = c2332lw5;
        } else if (abstractC2547qwG instanceof C2247jx) {
            c2332lw = c2332lw4;
        } else if (abstractC2547qwG instanceof Hw) {
            c2332lw = c2332lw3;
        } else if (abstractC2547qwG instanceof Mw) {
            c2332lw = c2332lw2;
        } else {
            if (!(abstractC2547qwG instanceof Sw)) {
                throw new GeneralSecurityException("Unsupported DEK parameters when parsing ".concat(abstractC2547qwG.toString()));
            }
            c2332lw = obj;
        }
        int iOrdinal = yz.ordinal();
        Ew ew = Ew.l;
        if (iOrdinal == 1) {
            ew = Ew.k;
        } else if (iOrdinal != 3) {
            throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
        }
        String strA = xz.A();
        AbstractC2804ww abstractC2804ww = (AbstractC2804ww) abstractC2547qwG;
        if (strA == null) {
            throw new GeneralSecurityException("kekUri must be set");
        }
        if (abstractC2804ww == null) {
            throw new GeneralSecurityException("dekParametersForNewKeys must be set");
        }
        if (abstractC2804ww.a()) {
            throw new GeneralSecurityException("dekParametersForNewKeys must not have ID Requirements");
        }
        if ((c2332lw.equals(c2332lw6) && (abstractC2804ww instanceof Pw)) || ((c2332lw.equals(c2332lw5) && (abstractC2804ww instanceof Vw)) || ((c2332lw.equals(c2332lw4) && (abstractC2804ww instanceof C2247jx)) || ((c2332lw.equals(c2332lw3) && (abstractC2804ww instanceof Hw)) || ((c2332lw.equals(c2332lw2) && (abstractC2804ww instanceof Mw)) || (c2332lw.equals(obj) && (abstractC2804ww instanceof Sw))))))) {
            return new C1943cx(ew, strA, c2332lw, abstractC2804ww);
        }
        throw new GeneralSecurityException(androidx.compose.ui.node.B.j(new StringBuilder("Cannot use parsing strategy "), c2332lw.b, " when new keys are picked according to ", String.valueOf(abstractC2804ww), "."));
    }

    public static Xz b(C1943cx c1943cx) {
        byte[] bArrD = ((C2420ny) Xx.b.d(c1943cx.d)).b.d();
        try {
            IA ia = IA.a;
            C2305lB c2305lB = C2305lB.c;
            Gz gzY = Gz.y(bArrD, IA.b);
            Wz wzX = Xz.x();
            String str = c1943cx.b;
            wzX.e();
            Xz.C((Xz) wzX.b, str);
            wzX.e();
            Xz.B((Xz) wzX.b, gzY);
            return (Xz) wzX.c();
        } catch (zzgzh e) {
            throw new GeneralSecurityException("Parsing KmsEnvelopeAeadKeyFormat failed: ", e);
        }
    }

    public static Yz c(Ew ew) throws GeneralSecurityException {
        if (Ew.k.equals(ew)) {
            return Yz.TINK;
        }
        if (Ew.l.equals(ew)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(ew)));
    }
}
