package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.h7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2129h7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    private static final C2129h7 zzg;
    private static volatile InterfaceC2219jB zzh;
    private int zzi;
    private int zzj;
    private F6 zzk;
    private F6 zzl;
    private F6 zzm;
    private VA zzn = C2348mB.e;
    private int zzo;

    static {
        C2129h7 c2129h7 = new C2129h7();
        zzg = c2129h7;
        OA.k(C2129h7.class, c2129h7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzg, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0001\u0000\u0001င\u0000\u0002ဉ\u0001\u0003ဉ\u0002\u0004ဉ\u0003\u0005\u001b\u0006င\u0004", new Object[]{"zzi", "zzj", "zzk", "zzl", "zzm", "zzn", F6.class, "zzo"});
        }
        if (iK == 3) {
            return new C2129h7();
        }
        if (iK == 4) {
            return new C1954d7(zzg);
        }
        if (iK == 5) {
            return zzg;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzh;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2129h7.class) {
            try {
                na = zzh;
                if (na == null) {
                    na = new NA();
                    zzh = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
