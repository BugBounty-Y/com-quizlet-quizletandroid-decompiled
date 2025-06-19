package com.google.android.gms.internal.ads;

import android.media.LoudnessCodecController;
import android.media.MediaCodec;
import android.util.SparseArray;
import android.util.SparseBooleanArray;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/* loaded from: classes2.dex */
public final class Fp implements Pv, Pk, InterfaceC2491pj {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public Fp(int i) {
        this.a = i;
        switch (i) {
            case 5:
                break;
            case 7:
                this.b = new HashMap();
                break;
            case 12:
                this.b = new HashSet();
                break;
            default:
                C2883yp c2883yp = new C2883yp(3, (byte) 0);
                this.b = c2883yp;
                this.c = new Sq(c2883yp);
                break;
        }
    }

    private final void e(Object obj) {
    }

    public Object a(C2418nw c2418nw) {
        return ((C2291ky) this.b).a(c2418nw.a, ((InterfaceC2334ly) this.c).zza());
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        switch (this.a) {
            case 10:
                ((SD) obj).o((RD) this.b, (androidx.compose.animation.core.S0) this.c);
                break;
            default:
                ((InterfaceC2266kF) obj).b(0, ((C2866yE) this.b).a, (androidx.compose.animation.core.S0) this.c);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 1:
                ((Lq) ((C2084g6) this.c).f).c.j1(new C2883yp((Iq) this.b, 1));
                break;
        }
    }

    public synchronized Map d() {
        try {
            if (((Map) this.c) == null) {
                this.c = Collections.unmodifiableMap(new HashMap((HashMap) this.b));
            }
        } catch (Throwable th) {
            throw th;
        }
        return (Map) this.c;
    }

    public void f(MediaCodec mediaCodec) {
        LoudnessCodecController loudnessCodecController;
        if (!((HashSet) this.b).remove(mediaCodec) || (loudnessCodecController = (LoudnessCodecController) this.c) == null) {
            return;
        }
        loudnessCodecController.removeMediaCodec(mediaCodec);
    }

    public boolean g(int i) {
        return ((C2049fF) this.b).a.get(i);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 1:
                ((Lq) ((C2084g6) this.c).f).c.j1(new Fi(26, (Iq) this.b, th));
                break;
            default:
                Pq pq = (Pq) this.c;
                pq.g(th);
                pq.h(false);
                ((Tq) this.b).a(pq);
                break;
        }
    }

    public /* synthetic */ Fp(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    public /* synthetic */ Fp(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public /* synthetic */ Fp(MediaCodec.CryptoInfo cryptoInfo) {
        this.a = 8;
        this.b = cryptoInfo;
        this.c = new MediaCodec.CryptoInfo.Pattern(0, 0);
    }

    public Fp(C2049fF c2049fF, SparseArray sparseArray) {
        this.a = 9;
        this.b = c2049fF;
        SparseBooleanArray sparseBooleanArray = c2049fF.a;
        SparseArray sparseArray2 = new SparseArray(sparseBooleanArray.size());
        for (int i = 0; i < sparseBooleanArray.size(); i++) {
            int iA = c2049fF.a(i);
            RD rd = (RD) sparseArray.get(iA);
            rd.getClass();
            sparseArray2.append(iA, rd);
        }
        this.c = sparseArray2;
    }
}
