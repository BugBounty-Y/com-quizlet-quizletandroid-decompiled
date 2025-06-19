package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Ez extends OA {
    private static final Ez zza;
    private static volatile InterfaceC2219jB zzb;
    private String zzc = "";
    private BA zzd = BA.b;
    private int zze;

    static {
        Ez ez = new Ez();
        zza = ez;
        OA.k(Ez.class, ez);
    }

    public static void B(Ez ez, int i) {
        int i2;
        if (i == 6) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        switch (i) {
            case 1:
                i2 = 0;
                break;
            case 2:
                i2 = 1;
                break;
            case 3:
                i2 = 2;
                break;
            case 4:
                i2 = 3;
                break;
            case 5:
                i2 = 4;
                break;
            case 6:
                i2 = -1;
                break;
            default:
                throw null;
        }
        ez.zze = i2;
    }

    public static /* synthetic */ void C(Ez ez, String str) {
        str.getClass();
        ez.zzc = str;
    }

    public static /* synthetic */ void D(Ez ez, BA ba) {
        ba.getClass();
        ez.zzd = ba;
    }

    public static Dz w() {
        return (Dz) zza.g();
    }

    public static Ez y() {
        return zza;
    }

    public final String A() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0000\u0001\u0003\u0003\u0000\u0000\u0000\u0001Ȉ\u0002\n\u0003\f", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new Ez();
        }
        if (iK == 4) {
            return new Dz(zza);
        }
        if (iK == 5) {
            return zza;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzb;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (Ez.class) {
            try {
                na = zzb;
                if (na == null) {
                    na = new NA();
                    zzb = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0014 A[PHI: r2
  0x0014: PHI (r2v1 int) = (r2v0 int), (r2v2 int) binds: [B:5:0x0006, B:9:0x000c] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int x() {
        /*
            r3 = this;
            int r0 = r3.zze
            r1 = 1
            if (r0 == 0) goto L15
            r2 = 2
            if (r0 == r1) goto L14
            r1 = 3
            if (r0 == r2) goto L15
            r2 = 4
            if (r0 == r1) goto L14
            if (r0 == r2) goto L12
            r1 = 0
            goto L15
        L12:
            r1 = 5
            goto L15
        L14:
            r1 = r2
        L15:
            if (r1 != 0) goto L19
            r0 = 6
            return r0
        L19:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Ez.x():int");
    }

    public final BA z() {
        return this.zzd;
    }
}
