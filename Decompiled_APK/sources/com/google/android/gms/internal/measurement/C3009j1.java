package com.google.android.gms.internal.measurement;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.measurement.j1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3009j1 extends W1 {
    private static final C3009j1 zzb;
    private int zzd;
    private int zze;
    private int zzf;
    private int zzg;

    static {
        C3009j1 c3009j1 = new C3009j1();
        zzb = c3009j1;
        W1.j(C3009j1.class, c3009j1);
    }

    public static C3004i1 n() {
        return (C3004i1) zzb.e();
    }

    public static C3009j1 p() {
        return zzb;
    }

    public static void q(C3009j1 c3009j1, int i) {
        c3009j1.zzf = AbstractC1642h.f(i);
        c3009j1.zzd |= 2;
    }

    public static /* synthetic */ void t(C3009j1 c3009j1, int i) {
        c3009j1.zzg = i - 1;
        c3009j1.zzd |= 4;
    }

    public static /* synthetic */ void u(C3009j1 c3009j1, int i) {
        c3009j1.zze = i - 1;
        c3009j1.zzd |= 1;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001᠌\u0000\u0002᠌\u0001\u0003᠌\u0002", new Object[]{"zzd", "zze", C3047r0.k, "zzf", C3047r0.i, "zzg", C3047r0.j});
        }
        if (i2 == 3) {
            return new C3009j1();
        }
        if (i2 == 4) {
            return new C3004i1(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int o() {
        int iA = AbstractC1642h.a(this.zzf);
        if (iA == 0) {
            return 1;
        }
        return iA;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0017 A[PHI: r3
  0x0017: PHI (r3v1 int) = (r3v0 int), (r3v2 int) binds: [B:7:0x0009, B:11:0x000f] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int r() {
        /*
            r4 = this;
            int r0 = r4.zzg
            r1 = 1
            if (r0 == 0) goto L19
            r2 = 2
            if (r0 == r1) goto L1a
            r3 = 3
            if (r0 == r2) goto L17
            r2 = 4
            if (r0 == r3) goto L1a
            r3 = 5
            if (r0 == r2) goto L17
            if (r0 == r3) goto L15
            r2 = 0
            goto L1a
        L15:
            r2 = 6
            goto L1a
        L17:
            r2 = r3
            goto L1a
        L19:
            r2 = r1
        L1a:
            if (r2 != 0) goto L1d
            return r1
        L1d:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.measurement.C3009j1.r():int");
    }

    public final int s() {
        int i;
        int i2 = this.zze;
        if (i2 != 0) {
            i = 2;
            if (i2 != 1) {
                if (i2 != 2) {
                    i = 4;
                    if (i2 != 3) {
                        i = i2 != 4 ? 0 : 5;
                    }
                } else {
                    i = 3;
                }
            }
        } else {
            i = 1;
        }
        if (i == 0) {
            return 1;
        }
        return i;
    }
}
