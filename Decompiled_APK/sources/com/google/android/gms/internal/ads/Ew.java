package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Ew implements Pv, Xh {
    public static final Ew c;
    public static final Ew d;
    public static final Ew e;
    public static final Ew f;
    public static final Ew g;
    public static final Ew h;
    public static final Ew i;
    public static final Ew j;
    public static final Ew k;
    public static final Ew l;
    public final /* synthetic */ int a;
    public final String b;

    static {
        int i2 = 0;
        c = new Ew("SHA1", i2);
        d = new Ew("SHA224", i2);
        e = new Ew("SHA256", i2);
        f = new Ew("SHA384", i2);
        g = new Ew("SHA512", i2);
        int i3 = 1;
        h = new Ew("TINK", i3);
        i = new Ew("CRUNCHY", i3);
        j = new Ew("NO_PREFIX", i3);
        int i4 = 2;
        k = new Ew("TINK", i4);
        l = new Ew("NO_PREFIX", i4);
    }

    public /* synthetic */ Ew(String str, int i2) {
        this.a = i2;
        this.b = str;
    }

    public static Ew a(Kn kn) {
        String str;
        kn.k(2);
        int iZ = kn.z();
        int i2 = iZ >> 1;
        int i3 = iZ & 1;
        int iZ2 = kn.z() >> 3;
        if (i2 == 4 || i2 == 5 || i2 == 7 || i2 == 8) {
            str = "dvhe";
        } else if (i2 == 9) {
            str = "dvav";
        } else {
            if (i2 != 10) {
                return null;
            }
            str = "dav1";
        }
        int i4 = iZ2 | (i3 << 5);
        StringBuilder sbU = androidx.compose.animation.d0.u(str);
        sbU.append(i2 < 10 ? ".0" : ".");
        sbU.append(i2);
        sbU.append(i4 < 10 ? ".0" : ".");
        sbU.append(i4);
        return new Ew(sbU.toString(), 6);
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        switch (this.a) {
            case 4:
                ((InterfaceC1928ci) obj).I(this.b);
                break;
            default:
                ((InterfaceC2618si) obj).a(this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return this.b;
            case 1:
                return this.b;
            case 2:
                return this.b;
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        com.google.android.gms.ads.internal.j.C.h.g(this.b, th);
    }
}
