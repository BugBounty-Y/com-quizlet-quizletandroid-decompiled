package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.nC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2392nC extends OA {
    private static final C2392nC zza;
    private static volatile InterfaceC2219jB zzb;
    private VA zzA;
    private VA zzB;
    private C2306lC zzC;
    private VA zzD;
    private OB zzE;
    private String zzF;
    private JB zzG;
    private VA zzH;
    private ZB zzI;
    private int zzJ;
    private VA zzK;
    private VA zzL;
    private long zzM;
    private C2349mC zzN;
    private C1915cC zzO;
    private String zzP;
    private int zzc;
    private int zzd;
    private int zze;
    private MB zzi;
    private VA zzj;
    private VA zzk;
    private String zzl;
    private C2090gC zzm;
    private boolean zzn;
    private VA zzo;
    private String zzp;
    private boolean zzu;
    private boolean zzv;
    private BA zzw;
    private C2263kC zzx;
    private boolean zzy;
    private String zzz;
    private byte zzQ = 2;
    private String zzf = "";
    private String zzg = "";
    private String zzh = "";

    static {
        C2392nC c2392nC = new C2392nC();
        zza = c2392nC;
        OA.k(C2392nC.class, c2392nC);
    }

    public C2392nC() {
        C2348mB c2348mB = C2348mB.e;
        this.zzj = c2348mB;
        this.zzk = c2348mB;
        this.zzl = "";
        this.zzo = c2348mB;
        this.zzp = "";
        this.zzw = BA.b;
        this.zzz = "";
        this.zzA = c2348mB;
        this.zzB = c2348mB;
        this.zzD = c2348mB;
        this.zzF = "";
        this.zzH = c2348mB;
        this.zzK = c2348mB;
        this.zzL = c2348mB;
        this.zzP = "";
    }

    public static void A(C2392nC c2392nC, ArrayList arrayList) {
        VA va = c2392nC.zzA;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2392nC.zzA = va.d(size + size);
        }
        AbstractC2647tA.c(arrayList, c2392nC.zzA);
    }

    public static void B(C2392nC c2392nC, ArrayList arrayList) {
        VA va = c2392nC.zzB;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2392nC.zzB = va.d(size + size);
        }
        AbstractC2647tA.c(arrayList, c2392nC.zzB);
    }

    public static void C(C2392nC c2392nC, C2178iC c2178iC) {
        VA va = c2392nC.zzj;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2392nC.zzj = va.d(size + size);
        }
        c2392nC.zzj.add(c2178iC);
    }

    public static /* synthetic */ void D(C2392nC c2392nC) {
        c2392nC.zzc &= -65;
        c2392nC.zzl = zza.zzl;
    }

    public static /* synthetic */ void E(C2392nC c2392nC, String str) {
        c2392nC.zzc |= 64;
        c2392nC.zzl = str;
    }

    public static /* synthetic */ void F(C2392nC c2392nC, C2263kC c2263kC) {
        c2392nC.zzx = c2263kC;
        c2392nC.zzc |= 8192;
    }

    public static /* synthetic */ void G(C2392nC c2392nC, MB mb) {
        c2392nC.zzi = mb;
        c2392nC.zzc |= 32;
    }

    public static /* synthetic */ void H(C2392nC c2392nC, String str) {
        c2392nC.zzc |= 8;
        c2392nC.zzg = str;
    }

    public static /* synthetic */ void I(C2392nC c2392nC, C2090gC c2090gC) {
        c2392nC.zzm = c2090gC;
        c2392nC.zzc |= 128;
    }

    public static /* synthetic */ void J(C2392nC c2392nC, String str) {
        c2392nC.zzc |= 4;
        c2392nC.zzf = str;
    }

    public static /* synthetic */ void K(C2392nC c2392nC, int i) {
        c2392nC.zzd = i - 1;
        c2392nC.zzc |= 1;
    }

    public static KB w() {
        return (KB) zza.g();
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return Byte.valueOf(this.zzQ);
            case 1:
                this.zzQ = oa == null ? (byte) 0 : (byte) 1;
                return null;
            case 2:
                return new C2391nB(zza, "\u0001#\u0000\u0001\u0001##\u0000\t\u0001\u0001ဈ\u0002\u0002ဈ\u0003\u0003ဈ\u0004\u0004Л\u0005ဇ\b\u0006\u001a\u0007ဈ\t\bဇ\n\tဇ\u000b\n᠌\u0000\u000b᠌\u0001\fဉ\u0005\rဈ\u0006\u000eဉ\u0007\u000fည\f\u0010\u001b\u0011ဉ\r\u0012ဇ\u000e\u0013ဈ\u000f\u0014\u001a\u0015\u001a\u0016ဉ\u0010\u0017\u001b\u0018ဉ\u0011\u0019ဈ\u0012\u001aဉ\u0013\u001b\u001b\u001cဉ\u0014\u001d᠌\u0015\u001e\u001b\u001f\u001b ဂ\u0016!ဉ\u0017\"ဉ\u0018#ဈ\u0019", new Object[]{"zzc", "zzf", "zzg", "zzh", "zzj", C2178iC.class, "zzn", "zzo", "zzp", "zzu", "zzv", "zzd", C1828aC.e, "zze", U3.B, "zzi", "zzl", "zzm", "zzw", "zzk", C2478pC.class, "zzx", "zzy", "zzz", "zzA", "zzB", "zzC", "zzD", C2606sC.class, "zzE", "zzF", "zzG", "zzH", PB.class, "zzI", "zzJ", C1828aC.h, "zzK", C1872bC.class, "zzL", C1959dC.class, "zzM", "zzN", "zzO", "zzP"});
            case 3:
                return new C2392nC();
            case 4:
                return new KB(zza);
            case 5:
                return zza;
            case 6:
                InterfaceC2219jB interfaceC2219jB = zzb;
                if (interfaceC2219jB != null) {
                    return interfaceC2219jB;
                }
                synchronized (C2392nC.class) {
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
            default:
                throw null;
        }
    }

    public final String x() {
        return this.zzl;
    }

    public final String y() {
        return this.zzf;
    }

    public final VA z() {
        return this.zzj;
    }
}
