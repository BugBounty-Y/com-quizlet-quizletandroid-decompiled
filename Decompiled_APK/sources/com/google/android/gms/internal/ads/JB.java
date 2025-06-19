package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class JB extends OA {
    private static final JB zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private boolean zze;
    private String zzf = "";
    private VA zzg;
    private int zzh;
    private boolean zzi;
    private boolean zzj;
    private boolean zzk;
    private String zzl;
    private int zzm;
    private int zzn;
    private int zzo;
    private boolean zzp;
    private VA zzu;
    private boolean zzv;
    private long zzw;
    private SA zzx;
    private boolean zzy;
    private SA zzz;

    static {
        JB jb = new JB();
        zza = jb;
        OA.k(JB.class, jb);
    }

    public JB() {
        C2348mB c2348mB = C2348mB.e;
        this.zzg = c2348mB;
        this.zzl = "";
        this.zzu = c2348mB;
        PA pa = PA.e;
        this.zzx = pa;
        this.zzz = pa;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0013\u0000\u0001\u0001\u0013\u0013\u0000\u0004\u0000\u0001᠌\u0000\u0002ဇ\u0001\u0003ဈ\u0002\u0004\u001a\u0005᠌\u0003\u0006ဇ\u0004\u0007ဇ\u0005\bဇ\u0006\tဈ\u0007\nင\b\u000bင\t\fင\n\rဇ\u000b\u000e\u001b\u000fဇ\f\u0010ဂ\r\u0011ࠬ\u0012ဇ\u000e\u0013ࠬ", new Object[]{"zzc", "zzd", U3.A, "zze", "zzf", "zzg", "zzh", U3.y, "zzi", "zzj", "zzk", "zzl", "zzm", "zzn", "zzo", "zzp", "zzu", IB.class, "zzv", "zzw", "zzx", U3.w, "zzy", "zzz", U3.z});
        }
        if (iK == 3) {
            return new JB();
        }
        if (iK == 4) {
            return new C1954d7(zza);
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
        synchronized (JB.class) {
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
}
