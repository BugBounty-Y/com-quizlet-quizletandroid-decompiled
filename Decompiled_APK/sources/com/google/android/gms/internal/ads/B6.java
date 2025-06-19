package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class B6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    public static final int zzg = 7;
    public static final int zzh = 8;
    public static final int zzi = 9;
    public static final int zzj = 10;
    public static final int zzk = 11;
    private static final B6 zzl;
    private static volatile InterfaceC2219jB zzm;
    private int zzA;
    private int zzB;
    private C6 zzC;
    private int zzn;
    private int zzo = 1000;
    private int zzp = 1000;
    private int zzu;
    private int zzv;
    private int zzw;
    private int zzx;
    private int zzy;
    private int zzz;

    static {
        B6 b6 = new B6();
        zzl = b6;
        OA.k(B6.class, b6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            U3 u3 = U3.t;
            return new C2391nB(zzl, "\u0004\u000b\u0000\u0001\u0001\u000b\u000b\u0000\u0000\u0000\u0001᠌\u0000\u0002᠌\u0001\u0003င\u0002\u0004င\u0003\u0005င\u0004\u0006င\u0005\u0007င\u0006\bင\u0007\tင\b\nင\t\u000bဉ\n", new Object[]{"zzn", "zzo", u3, "zzp", u3, "zzu", "zzv", "zzw", "zzx", "zzy", "zzz", "zzA", "zzB", "zzC"});
        }
        if (iK == 3) {
            return new B6();
        }
        if (iK == 4) {
            return new W3(zzl);
        }
        if (iK == 5) {
            return zzl;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzm;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (B6.class) {
            try {
                na = zzm;
                if (na == null) {
                    na = new NA();
                    zzm = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
