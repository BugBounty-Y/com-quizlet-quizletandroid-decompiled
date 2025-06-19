package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.ads.hB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2133hB implements InterfaceC2562rB {
    public final AbstractC2647tA a;
    public final C1 b;

    public C2133hB(C1 c1, AbstractC2647tA abstractC2647tA) {
        C2806wy c2806wy = JA.a;
        this.b = c1;
        this.a = abstractC2647tA;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void a(Object obj) {
        this.b.getClass();
        C2691uB c2691uB = ((OA) obj).zzt;
        if (c2691uB.e) {
            c2691uB.e = false;
        }
        C2806wy c2806wy = JA.a;
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void b(Object obj, Object obj2) {
        AbstractC2605sB.s(obj, obj2);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void c(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        OA oa = (OA) obj;
        if (oa.zzt == C2691uB.f) {
            oa.zzt = C2691uB.b();
        }
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final boolean d(Object obj) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void e(Object obj, C2586rt c2586rt) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final int f(OA oa) {
        return oa.zzt.hashCode();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final int g(OA oa) {
        C2691uB c2691uB = oa.zzt;
        int i = c2691uB.d;
        if (i != -1) {
            return i;
        }
        int iG = 0;
        for (int i2 = 0; i2 < c2691uB.a; i2++) {
            int i3 = c2691uB.b[i2] >>> 3;
            BA ba = (BA) c2691uB.c[i2];
            int iC = HA.C(8);
            int iC2 = HA.C(i3) + HA.C(16);
            int iC3 = HA.C(24);
            int iG2 = ba.g();
            iG += iC + iC + iC2 + AbstractC1642h.g(iG2, iG2, iC3);
        }
        c2691uB.d = iG;
        return iG;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final boolean h(OA oa, OA oa2) {
        return oa.zzt.equals(oa2.zzt);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final void i(Object obj, androidx.compose.runtime.changelist.K k, IA ia) {
        this.b.getClass();
        C1.r(obj);
        obj.getClass();
        throw new ClassCastException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2562rB
    public final OA zze() {
        AbstractC2647tA abstractC2647tA = this.a;
        return abstractC2647tA instanceof OA ? ((OA) abstractC2647tA).n() : ((MA) ((OA) abstractC2647tA).s(5, null)).d();
    }
}
