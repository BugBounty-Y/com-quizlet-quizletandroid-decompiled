package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class T3 extends OA {
    private static final T3 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private boolean zzg;
    private Z3 zzi;
    private C1820a4 zzj;
    private boolean zzk;
    private boolean zze = true;
    private String zzf = "unknown_host";
    private boolean zzh = true;

    static {
        T3 t3 = new T3();
        zza = t3;
        OA.k(T3.class, t3);
    }

    public static /* synthetic */ void A(T3 t3, boolean z) {
        t3.zzc |= 8;
        t3.zzg = z;
    }

    public static /* synthetic */ void B(T3 t3, String str) {
        str.getClass();
        t3.zzc |= 4;
        t3.zzf = str;
    }

    public static S3 w() {
        return (S3) zza.g();
    }

    public final boolean C() {
        return this.zzg;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\b\u0000\u0001\u0001\b\b\u0000\u0000\u0000\u0001᠌\u0000\u0002ဇ\u0001\u0003ဈ\u0002\u0004ဇ\u0003\u0005ဇ\u0004\u0006ဉ\u0005\u0007ဉ\u0006\bဇ\u0007", new Object[]{"zzc", "zzd", U3.b, "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk"});
        }
        if (iK == 3) {
            return new T3();
        }
        if (iK == 4) {
            return new S3(zza);
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
        synchronized (T3.class) {
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

    public final Z3 x() {
        Z3 z3 = this.zzi;
        return z3 == null ? Z3.x() : z3;
    }

    public final void y() {
        if (this.zzj == null) {
            int i = C1820a4.zza;
        }
    }

    public final String z() {
        return this.zzf;
    }
}
