package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public final /* synthetic */ class Cw {
    public final /* synthetic */ int a;

    public /* synthetic */ Cw(int i) {
        this.a = i;
    }

    public final AbstractC2025es a(AbstractC2547qw abstractC2547qw, Integer num) throws GeneralSecurityException {
        boolean z = false;
        switch (this.a) {
            case 0:
                Hw hw = (Hw) abstractC2547qw;
                C2163hy c2163hy = Dw.a;
                int i = hw.a;
                if (i != 16 && i != 32) {
                    throw new GeneralSecurityException("AES key size must be 16 or 32 bytes");
                }
                com.quizlet.data.repository.explanations.question.a aVar = new com.quizlet.data.repository.explanations.question.a();
                aVar.a = hw;
                aVar.d = num;
                aVar.b = C2883yp.h(i);
                aVar.c = C2883yp.h(hw.b);
                return aVar.i();
            case 1:
                Mw mw = (Mw) abstractC2547qw;
                C2163hy c2163hy2 = Kw.a;
                int i2 = mw.a;
                if (i2 == 24) {
                    throw new GeneralSecurityException("192 bit AES GCM Parameters are not valid");
                }
                Iw iw = new Iw(z);
                iw.c = mw;
                iw.b = num;
                iw.a = C2883yp.h(i2);
                return iw.e();
            case 2:
                Pw pw = (Pw) abstractC2547qw;
                C2163hy c2163hy3 = Ow.a;
                int i3 = pw.a;
                if (i3 == 24) {
                    throw new GeneralSecurityException("192 bit AES GCM Parameters are not valid");
                }
                Iw iw2 = new Iw(z);
                iw2.c = pw;
                iw2.b = num;
                iw2.a = C2883yp.h(i3);
                return iw2.f();
            case 3:
                Sw sw = (Sw) abstractC2547qw;
                C2163hy c2163hy4 = Rw.a;
                Iw iw3 = new Iw(z);
                iw3.c = sw;
                iw3.b = num;
                iw3.a = C2883yp.h(sw.a);
                return iw3.g();
            case 4:
                C2163hy c2163hy5 = Uw.a;
                return Tw.S(((Vw) abstractC2547qw).a, C2883yp.h(32), num);
            case 5:
                C2163hy c2163hy6 = Ww.a;
                return Yw.S((Zw) abstractC2547qw, num);
            case 6:
                Kx kx = Xw.a;
                return C1900bx.S((C1943cx) abstractC2547qw, num);
            case 7:
                return C2074fx.S((C2118gx) abstractC2547qw, C2883yp.h(32), num);
            case 8:
                C2163hy c2163hy7 = AbstractC2204ix.a;
                return C2162hx.S(((C2247jx) abstractC2547qw).a, C2883yp.h(32), num);
            case 9:
                Qx qx = Qx.b;
                C2420ny c2420ny = ((Ox) abstractC2547qw).a;
                Fx fx = Fx.d;
                Gz gz = c2420ny.b;
                Kx kxD = fx.d(gz.B());
                if (!((Boolean) fx.b.get(gz.B())).booleanValue()) {
                    throw new GeneralSecurityException("Creating new keys is not allowed.");
                }
                BA baA = gz.A();
                kxD.getClass();
                Fz fzW = Gz.w();
                fzW.h(kxD.a);
                fzW.i(baA);
                fzW.g(Yz.RAW);
                Gz gz2 = (Gz) fzW.c();
                C2420ny c2420ny2 = new C2420ny(gz2, AbstractC2677ty.a(gz2.B()));
                Xx xx = Xx.b;
                C2377my c2377my = (C2377my) xx.c(Qx.b.a(xx.b(c2420ny2), null));
                Dz dzW = Ez.w();
                dzW.e();
                Ez.C((Ez) dzW.b, c2377my.a);
                dzW.e();
                Ez.D((Ez) dzW.b, c2377my.c);
                dzW.e();
                Ez.B((Ez) dzW.b, c2377my.d);
                Ez ez = (Ez) dzW.c();
                return new Nx(C2377my.a(ez.A(), ez.z(), ez.x(), gz.z(), num));
            case 10:
                C2892yy c2892yy = (C2892yy) abstractC2547qw;
                int i4 = c2892yy.a;
                if (i4 != 32) {
                    throw new GeneralSecurityException("AesCmacKey size wrong, must be 32 bytes");
                }
                Iw iw4 = new Iw(z);
                iw4.c = c2892yy;
                iw4.a = C2883yp.h(i4);
                iw4.b = num;
                return iw4.h();
            default:
                Ey ey = (Ey) abstractC2547qw;
                C2163hy c2163hy8 = By.a;
                Iw iw5 = new Iw(z);
                iw5.c = ey;
                iw5.a = C2883yp.h(ey.a);
                iw5.b = num;
                return iw5.j();
        }
    }
}
