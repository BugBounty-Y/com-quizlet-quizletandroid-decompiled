package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import java.io.IOException;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class RE implements InterfaceC2266kF, InterfaceC2909zE {
    public final Integer a;
    public C2866yE b;
    public C2866yE c;
    public final /* synthetic */ TE d;

    public RE(TE te, Integer num) {
        this.d = te;
        this.b = new C2866yE(te.c.b, null);
        this.c = new C2866yE(te.d.b, null);
        this.a = num;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void a(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) throws RemoteException, IOException {
        if (g(c2093gF)) {
            C2866yE c2866yE = this.b;
            f(s0, c2093gF);
            c2866yE.getClass();
            c2866yE.a(new Bs(c2866yE, ye, s0, iOException, z));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void b(int i, C2093gF c2093gF, androidx.compose.animation.core.S0 s0) throws RemoteException, IOException {
        if (g(c2093gF)) {
            C2866yE c2866yE = this.b;
            f(s0, c2093gF);
            c2866yE.getClass();
            c2866yE.a(new Fp(c2866yE, false, s0, 13));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void c(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) throws RemoteException, IOException {
        if (g(c2093gF)) {
            C2866yE c2866yE = this.b;
            f(s0, c2093gF);
            c2866yE.getClass();
            c2866yE.a(new C2181iF(c2866yE, ye, s0, 0));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void d(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0, int i2) throws RemoteException, IOException {
        if (g(c2093gF)) {
            C2866yE c2866yE = this.b;
            f(s0, c2093gF);
            c2866yE.getClass();
            c2866yE.a(new As(c2866yE, ye, s0, i2));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void e(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) throws RemoteException, IOException {
        if (g(c2093gF)) {
            C2866yE c2866yE = this.b;
            f(s0, c2093gF);
            c2866yE.getClass();
            c2866yE.a(new C2181iF(c2866yE, ye, s0, 1));
        }
    }

    public final void f(androidx.compose.animation.core.S0 s0, C2093gF c2093gF) {
        TE te = this.d;
        Integer num = this.a;
        te.v(s0.b, num);
        te.v(s0.c, num);
    }

    public final boolean g(C2093gF c2093gF) {
        C2093gF c2093gFW;
        Integer num = this.a;
        TE te = this.d;
        if (c2093gF != null) {
            c2093gFW = te.w(num, c2093gF);
            if (c2093gFW == null) {
                return false;
            }
        } else {
            c2093gFW = null;
        }
        te.u(num);
        C2866yE c2866yE = this.b;
        c2866yE.getClass();
        if (!Objects.equals(c2866yE.a, c2093gFW)) {
            this.b = new C2866yE(te.c.b, c2093gFW);
        }
        C2866yE c2866yE2 = this.c;
        c2866yE2.getClass();
        if (Objects.equals(c2866yE2.a, c2093gFW)) {
            return true;
        }
        this.c = new C2866yE(te.d.b, c2093gFW);
        return true;
    }
}
