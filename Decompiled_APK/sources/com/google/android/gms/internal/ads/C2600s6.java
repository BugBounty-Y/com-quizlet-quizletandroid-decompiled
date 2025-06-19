package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.s6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2600s6 extends OA {
    public static final int zza = 7;
    public static final int zzb = 8;
    public static final int zzc = 9;
    public static final int zzd = 10;
    public static final int zze = 11;
    public static final int zzf = 12;
    public static final int zzg = 13;
    public static final int zzh = 14;
    public static final int zzi = 15;
    public static final int zzj = 16;
    public static final int zzk = 17;
    private static final C2600s6 zzl;
    private static volatile InterfaceC2219jB zzm;
    private C2430o7 zzA;
    private C2473p7 zzB;
    private VA zzC;
    private int zzn;
    private int zzo;
    private int zzp = 1000;
    private C1997e7 zzu;
    private C2085g7 zzv;
    private VA zzw;
    private C2129h7 zzx;
    private B6 zzy;
    private C2729v6 zzz;

    static {
        C2600s6 c2600s6 = new C2600s6();
        zzl = c2600s6;
        OA.k(C2600s6.class, c2600s6);
    }

    public C2600s6() {
        C2348mB c2348mB = C2348mB.e;
        this.zzw = c2348mB;
        this.zzC = c2348mB;
    }

    public static void w(C2600s6 c2600s6, EnumC2515q6 enumC2515q6) {
        c2600s6.getClass();
        c2600s6.zzo = enumC2515q6.a;
        c2600s6.zzn |= 1;
    }

    public static void x(C2600s6 c2600s6, C2085g7 c2085g7) {
        c2600s6.getClass();
        c2600s6.zzv = c2085g7;
        c2600s6.zzn |= 8;
    }

    public static C2600s6 z() {
        return zzl;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzl, "\u0004\u000b\u0000\u0001\u0007\u0011\u000b\u0000\u0002\u0000\u0007᠌\u0000\b᠌\u0001\tဉ\u0002\nဉ\u0003\u000b\u001b\fဉ\u0004\rဉ\u0005\u000eဉ\u0006\u000fဉ\u0007\u0010ဉ\b\u0011\u001b", new Object[]{"zzn", "zzo", U3.l, "zzp", U3.t, "zzu", "zzv", "zzw", C1910c7.class, "zzx", "zzy", "zzz", "zzA", "zzB", "zzC", I6.class});
        }
        if (iK == 3) {
            return new C2600s6();
        }
        if (iK == 4) {
            return new C2557r6(zzl);
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
        synchronized (C2600s6.class) {
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

    public final C2085g7 y() {
        C2085g7 c2085g7 = this.zzv;
        return c2085g7 == null ? C2085g7.x() : c2085g7;
    }
}
