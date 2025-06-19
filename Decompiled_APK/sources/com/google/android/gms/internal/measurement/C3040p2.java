package com.google.android.gms.internal.measurement;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.ads.C2776wA;

/* renamed from: com.google.android.gms.internal.measurement.p2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3040p2 implements InterfaceC3069v2 {
    public final J1 a;
    public final U1 b;

    public C3040p2(U1 u1, J1 j1) {
        U1 u12 = R1.a;
        this.b = u1;
        this.a = j1;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void a(Object obj) {
        this.b.getClass();
        C3079x2 c3079x2 = ((W1) obj).zzc;
        if (c3079x2.e) {
            c3079x2.e = false;
        }
        U1 u1 = R1.a;
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void b(Object obj, Object obj2) {
        AbstractC3074w2.p(obj, obj2);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final boolean c(Object obj) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void d(Object obj, C3005i2 c3005i2) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final int e(W1 w1) {
        C3079x2 c3079x2 = w1.zzc;
        int i = c3079x2.d;
        if (i != -1) {
            return i;
        }
        int iW = 0;
        for (int i2 = 0; i2 < c3079x2.a; i2++) {
            int i3 = c3079x2.b[i2] >>> 3;
            O1 o1 = (O1) c3079x2.c[i2];
            int iQ = P1.q(8);
            int iQ2 = P1.q(i3) + P1.q(16);
            int iQ3 = P1.q(24);
            int iC = o1.c();
            iW += iQ + iQ + iQ2 + AbstractC1642h.w(iC, iC, iQ3);
        }
        c3079x2.d = iW;
        return iW;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final int f(W1 w1) {
        return w1.zzc.hashCode();
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final boolean g(W1 w1, W1 w12) {
        return w1.zzc.equals(w12.zzc);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final void h(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        W1 w1 = (W1) obj;
        if (w1.zzc == C3079x2.f) {
            w1.zzc = C3079x2.b();
        }
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3069v2
    public final W1 zze() {
        J1 j1 = this.a;
        return j1 instanceof W1 ? (W1) ((W1) j1).m(4) : ((V1) ((W1) j1).m(5)).g();
    }
}
