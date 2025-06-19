package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.lx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2333lx {
    public static final C1944cy a;
    public static final Zx b;
    public static final Ix c;
    public static final Gx d;

    static {
        C2604sA c2604sAB = AbstractC2677ty.b("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
        a = new C1944cy(Hw.class, new C2290kx(0));
        b = new Zx(c2604sAB, new C2290kx(1));
        c = new Ix(Aw.class, new C2290kx(2));
        d = new Gx(c2604sAB, new C2290kx(3));
    }

    public static Ew a(EnumC2764vz enumC2764vz) throws GeneralSecurityException {
        int iOrdinal = enumC2764vz.ordinal();
        if (iOrdinal == 1) {
            return Ew.c;
        }
        if (iOrdinal == 2) {
            return Ew.f;
        }
        if (iOrdinal == 3) {
            return Ew.e;
        }
        if (iOrdinal == 4) {
            return Ew.g;
        }
        if (iOrdinal == 5) {
            return Ew.d;
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.f(enumC2764vz.a(), "Unable to parse HashType: "));
    }

    public static Gw b(Yz yz) throws GeneralSecurityException {
        int iOrdinal = yz.ordinal();
        if (iOrdinal == 1) {
            return Gw.c;
        }
        if (iOrdinal != 2) {
            if (iOrdinal == 3) {
                return Gw.e;
            }
            if (iOrdinal != 4) {
                throw new GeneralSecurityException(android.support.v4.media.session.a.f(yz.a(), "Unable to parse OutputPrefixType: "));
            }
        }
        return Gw.d;
    }

    public static Cz c(Hw hw) {
        EnumC2764vz enumC2764vz;
        Bz bzY = Cz.y();
        int i = hw.d;
        bzY.e();
        ((Cz) bzY.b).zzd = i;
        Ew ew = Ew.c;
        Ew ew2 = hw.f;
        if (ew.equals(ew2)) {
            enumC2764vz = EnumC2764vz.SHA1;
        } else if (Ew.d.equals(ew2)) {
            enumC2764vz = EnumC2764vz.SHA224;
        } else if (Ew.e.equals(ew2)) {
            enumC2764vz = EnumC2764vz.SHA256;
        } else if (Ew.f.equals(ew2)) {
            enumC2764vz = EnumC2764vz.SHA384;
        } else {
            if (!Ew.g.equals(ew2)) {
                throw new GeneralSecurityException("Unable to serialize HashType ".concat(String.valueOf(ew2)));
            }
            enumC2764vz = EnumC2764vz.SHA512;
        }
        bzY.e();
        ((Cz) bzY.b).zzc = enumC2764vz.a();
        return (Cz) bzY.c();
    }

    public static Yz d(Gw gw) throws GeneralSecurityException {
        if (Gw.c.equals(gw)) {
            return Yz.TINK;
        }
        if (Gw.d.equals(gw)) {
            return Yz.CRUNCHY;
        }
        if (Gw.e.equals(gw)) {
            return Yz.RAW;
        }
        throw new GeneralSecurityException("Unable to serialize variant: ".concat(String.valueOf(gw)));
    }
}
