package com.google.android.gms.internal.play_billing;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.ads.C2776wA;

/* renamed from: com.google.android.gms.internal.play_billing.s1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3834s1 implements InterfaceC3852y1 {
    public final P0 a;
    public final C3781a1 b;

    public C3834s1(C3781a1 c3781a1, P0 p0) {
        C3781a1 c3781a12 = X0.a;
        this.b = c3781a1;
        this.a = p0;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void a(Object obj) {
        this.b.getClass();
        B1 b1 = ((AbstractC3787c1) obj).zzc;
        if (b1.e) {
            b1.e = false;
        }
        C3781a1 c3781a1 = X0.a;
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void b(Object obj, Object obj2) {
        AbstractC3855z1.p(obj, obj2);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final boolean c(Object obj) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final int d(AbstractC3787c1 abstractC3787c1) {
        B1 b1 = abstractC3787c1.zzc;
        int i = b1.d;
        if (i != -1) {
            return i;
        }
        int iY = 0;
        for (int i2 = 0; i2 < b1.a; i2++) {
            int i3 = b1.b[i2] >>> 3;
            U0 u0 = (U0) b1.c[i2];
            int iE0 = V0.e0(8);
            int iE02 = V0.e0(i3) + V0.e0(16);
            int iE03 = V0.e0(24);
            int iC = u0.c();
            iY += iE0 + iE0 + iE02 + AbstractC1642h.y(iC, iC, iE03);
        }
        b1.d = iY;
        return iY;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void e(Object obj, byte[] bArr, int i, int i2, C2776wA c2776wA) {
        AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) obj;
        if (abstractC3787c1.zzc == B1.f) {
            abstractC3787c1.zzc = B1.b();
        }
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final int f(AbstractC3787c1 abstractC3787c1) {
        return abstractC3787c1.zzc.hashCode();
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final boolean g(AbstractC3787c1 abstractC3787c1, AbstractC3787c1 abstractC3787c12) {
        return abstractC3787c1.zzc.equals(abstractC3787c12.zzc);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final void h(Object obj, C3817m1 c3817m1) {
        throw androidx.compose.animation.d0.l(obj);
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3852y1
    public final AbstractC3787c1 zze() {
        P0 p0 = this.a;
        return p0 instanceof AbstractC3787c1 ? (AbstractC3787c1) ((AbstractC3787c1) p0).d(4) : ((AbstractC3784b1) ((AbstractC3787c1) p0).d(5)).d();
    }
}
