package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class I6 extends OA {
    public static final int zza = 5;
    public static final int zzb = 6;
    public static final int zzc = 7;
    public static final int zzd = 8;
    public static final int zze = 9;
    public static final int zzf = 10;
    public static final int zzg = 11;
    public static final int zzh = 12;
    public static final int zzi = 13;
    public static final int zzj = 14;
    public static final int zzk = 15;
    public static final int zzl = 16;
    public static final int zzm = 17;
    public static final int zzn = 18;
    public static final int zzo = 19;
    public static final int zzp = 20;
    private static final I6 zzu;
    private static volatile InterfaceC2219jB zzv;
    private Y6 zzA;
    private J6 zzB;
    private V6 zzC;
    private L6 zzD;
    private int zzE;
    private int zzF;
    private F6 zzG;
    private int zzH;
    private int zzI;
    private int zzJ;
    private int zzK;
    private int zzL;
    private long zzM;
    private int zzw;
    private U6 zzx;
    private W6 zzy;
    private X6 zzz;

    static {
        I6 i6 = new I6();
        zzu = i6;
        OA.k(I6.class, i6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzu, "\u0004\u0010\u0000\u0001\u0005\u0014\u0010\u0000\u0000\u0000\u0005ဉ\u0000\u0006ဉ\u0001\u0007ဉ\u0002\bဉ\u0003\tဉ\u0004\nဉ\u0005\u000bဉ\u0006\fင\u0007\rင\b\u000eဉ\t\u000fင\n\u0010င\u000b\u0011င\f\u0012င\r\u0013င\u000e\u0014ဃ\u000f", new Object[]{"zzw", "zzx", "zzy", "zzz", "zzA", "zzB", "zzC", "zzD", "zzE", "zzF", "zzG", "zzH", "zzI", "zzJ", "zzK", "zzL", "zzM"});
        }
        if (iK == 3) {
            return new I6();
        }
        if (iK == 4) {
            return new W3(zzu);
        }
        if (iK == 5) {
            return zzu;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzv;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (I6.class) {
            try {
                na = zzv;
                if (na == null) {
                    na = new NA();
                    zzv = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
