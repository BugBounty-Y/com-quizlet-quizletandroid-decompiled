package androidx.compose.ui.platform;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import androidx.compose.animation.C0281h;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class K0 implements androidx.compose.ui.node.f0 {
    public final C0971v a;
    public C0281h b;
    public androidx.compose.ui.input.nestedscroll.b c;
    public boolean d;
    public boolean f;
    public boolean g;
    public com.google.android.gms.cloudmessaging.k h;
    public final InterfaceC0959o0 l;
    public int m;
    public final C0 e = new C0();
    public final C0978y0 i = new C0978y0(C0951k0.c);
    public final C0859t j = new C0859t();
    public long k = androidx.compose.ui.graphics.Z.b;

    public K0(C0971v c0971v, C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar) {
        this.a = c0971v;
        this.b = c0281h;
        this.c = bVar;
        InterfaceC0959o0 i0 = Build.VERSION.SDK_INT >= 29 ? new I0() : new G0(c0971v);
        i0.B();
        i0.t(false);
        this.l = i0;
    }

    @Override // androidx.compose.ui.node.f0
    public final void a(C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar) {
        l(false);
        this.f = false;
        this.g = false;
        this.k = androidx.compose.ui.graphics.Z.b;
        this.b = c0281h;
        this.c = bVar;
    }

    @Override // androidx.compose.ui.node.f0
    public final void b(float[] fArr) {
        androidx.compose.ui.graphics.J.g(fArr, this.i.b(this.l));
    }

    @Override // androidx.compose.ui.node.f0
    public final boolean c(long j) {
        androidx.compose.ui.graphics.N n;
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fE = androidx.compose.ui.geometry.b.e(j);
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        if (interfaceC0959o0.C()) {
            if (DefinitionKt.NO_Float_VALUE > fD || fD >= interfaceC0959o0.getWidth() || DefinitionKt.NO_Float_VALUE > fE || fE >= interfaceC0959o0.b()) {
                return false;
            }
        } else if (interfaceC0959o0.G()) {
            C0 c0 = this.e;
            if (c0.m && (n = c0.c) != null) {
                return N.z(n, androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
            }
            return true;
        }
        return true;
    }

    @Override // androidx.compose.ui.node.f0
    public final void d(androidx.compose.ui.graphics.S s) {
        androidx.compose.ui.input.nestedscroll.b bVar;
        int i = s.a | this.m;
        int i2 = i & 4096;
        if (i2 != 0) {
            this.k = s.n;
        }
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        boolean zG = interfaceC0959o0.G();
        C0 c0 = this.e;
        boolean z = false;
        boolean z2 = zG && c0.g;
        if ((i & 1) != 0) {
            interfaceC0959o0.j(s.b);
        }
        if ((i & 2) != 0) {
            interfaceC0959o0.g(s.c);
        }
        if ((i & 4) != 0) {
            interfaceC0959o0.i(s.d);
        }
        if ((i & 8) != 0) {
            interfaceC0959o0.k(s.e);
        }
        if ((i & 16) != 0) {
            interfaceC0959o0.e(s.f);
        }
        if ((i & 32) != 0) {
            interfaceC0959o0.x(s.g);
        }
        if ((i & 64) != 0) {
            interfaceC0959o0.E(androidx.compose.ui.graphics.F.A(s.h));
        }
        if ((i & 128) != 0) {
            interfaceC0959o0.I(androidx.compose.ui.graphics.F.A(s.i));
        }
        if ((i & 1024) != 0) {
            interfaceC0959o0.d(s.l);
        }
        if ((i & 256) != 0) {
            interfaceC0959o0.n(s.j);
        }
        if ((i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0) {
            interfaceC0959o0.c(s.k);
        }
        if ((i & 2048) != 0) {
            interfaceC0959o0.l(s.m);
        }
        if (i2 != 0) {
            interfaceC0959o0.s(androidx.compose.ui.graphics.Z.b(this.k) * interfaceC0959o0.getWidth());
            interfaceC0959o0.w(androidx.compose.ui.graphics.Z.c(this.k) * interfaceC0959o0.b());
        }
        boolean z3 = s.p;
        com.quizlet.shared.usecase.folderstudymaterials.d dVar = androidx.compose.ui.graphics.F.a;
        boolean z4 = z3 && s.o != dVar;
        if ((i & 24576) != 0) {
            interfaceC0959o0.H(z4);
            interfaceC0959o0.t(s.p && s.o == dVar);
        }
        if ((131072 & i) != 0) {
            interfaceC0959o0.m(s.u);
        }
        if ((32768 & i) != 0) {
            interfaceC0959o0.z(s.q);
        }
        boolean zC = this.e.c(s.v, s.d, z4, s.g, s.r);
        if (c0.f) {
            interfaceC0959o0.A(c0.b());
        }
        if (z4 && c0.g) {
            z = true;
        }
        C0971v c0971v = this.a;
        if (z2 == z && (!z || !zC)) {
            u1.a.a(c0971v);
        } else if (!this.d && !this.f) {
            c0971v.invalidate();
            l(true);
        }
        if (!this.g && interfaceC0959o0.K() > DefinitionKt.NO_Float_VALUE && (bVar = this.c) != null) {
            bVar.invoke();
        }
        if ((i & 7963) != 0) {
            this.i.c();
        }
        this.m = s.a;
    }

    @Override // androidx.compose.ui.node.f0
    public final void destroy() {
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        if (interfaceC0959o0.h()) {
            interfaceC0959o0.f();
        }
        this.b = null;
        this.c = null;
        this.f = true;
        l(false);
        C0971v c0971v = this.a;
        c0971v.z = true;
        c0971v.A(this);
    }

    @Override // androidx.compose.ui.node.f0
    public final long e(long j, boolean z) {
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        C0978y0 c0978y0 = this.i;
        if (!z) {
            return androidx.compose.ui.graphics.J.b(j, c0978y0.b(interfaceC0959o0));
        }
        float[] fArrA = c0978y0.a(interfaceC0959o0);
        if (fArrA != null) {
            return androidx.compose.ui.graphics.J.b(j, fArrA);
        }
        return 9187343241974906880L;
    }

    @Override // androidx.compose.ui.node.f0
    public final void f(long j) {
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        float fB = androidx.compose.ui.graphics.Z.b(this.k) * i;
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        interfaceC0959o0.s(fB);
        interfaceC0959o0.w(androidx.compose.ui.graphics.Z.c(this.k) * i2);
        if (interfaceC0959o0.u(interfaceC0959o0.r(), interfaceC0959o0.D(), interfaceC0959o0.r() + i, interfaceC0959o0.D() + i2)) {
            interfaceC0959o0.A(this.e.b());
            if (!this.d && !this.f) {
                this.a.invalidate();
                l(true);
            }
            this.i.c();
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void g(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        Canvas canvasA = AbstractC0845e.a(interfaceC0858s);
        boolean zIsHardwareAccelerated = canvasA.isHardwareAccelerated();
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        if (zIsHardwareAccelerated) {
            k();
            boolean z = interfaceC0959o0.K() > DefinitionKt.NO_Float_VALUE;
            this.g = z;
            if (z) {
                interfaceC0858s.t();
            }
            interfaceC0959o0.q(canvasA);
            if (this.g) {
                interfaceC0858s.f();
                return;
            }
            return;
        }
        float fR = interfaceC0959o0.r();
        float fD = interfaceC0959o0.D();
        float F = interfaceC0959o0.F();
        float fP = interfaceC0959o0.p();
        if (interfaceC0959o0.a() < 1.0f) {
            com.google.android.gms.cloudmessaging.k kVarG = this.h;
            if (kVarG == null) {
                kVarG = androidx.compose.ui.graphics.F.g();
                this.h = kVarG;
            }
            kVarG.d(interfaceC0959o0.a());
            canvasA.saveLayer(fR, fD, F, fP, (Paint) kVarG.c);
        } else {
            interfaceC0858s.e();
        }
        interfaceC0858s.p(fR, fD);
        interfaceC0858s.j(this.i.b(interfaceC0959o0));
        if (interfaceC0959o0.G() || interfaceC0959o0.C()) {
            this.e.a(interfaceC0858s);
        }
        C0281h c0281h = this.b;
        if (c0281h != null) {
            c0281h.invoke(interfaceC0858s, null);
        }
        interfaceC0858s.q();
        l(false);
    }

    @Override // androidx.compose.ui.node.f0
    public final void h(float[] fArr) {
        float[] fArrA = this.i.a(this.l);
        if (fArrA != null) {
            androidx.compose.ui.graphics.J.g(fArr, fArrA);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void i(androidx.camera.camera2.internal.q0 q0Var, boolean z) {
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        C0978y0 c0978y0 = this.i;
        if (!z) {
            androidx.compose.ui.graphics.J.c(c0978y0.b(interfaceC0959o0), q0Var);
            return;
        }
        float[] fArrA = c0978y0.a(interfaceC0959o0);
        if (fArrA != null) {
            androidx.compose.ui.graphics.J.c(fArrA, q0Var);
            return;
        }
        q0Var.b = DefinitionKt.NO_Float_VALUE;
        q0Var.c = DefinitionKt.NO_Float_VALUE;
        q0Var.d = DefinitionKt.NO_Float_VALUE;
        q0Var.e = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.ui.node.f0
    public final void invalidate() {
        if (this.d || this.f) {
            return;
        }
        this.a.invalidate();
        l(true);
    }

    @Override // androidx.compose.ui.node.f0
    public final void j(long j) {
        InterfaceC0959o0 interfaceC0959o0 = this.l;
        int iR = interfaceC0959o0.r();
        int iD = interfaceC0959o0.D();
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        if (iR == i && iD == i2) {
            return;
        }
        if (iR != i) {
            interfaceC0959o0.o(i - iR);
        }
        if (iD != i2) {
            interfaceC0959o0.y(i2 - iD);
        }
        u1.a.a(this.a);
        this.i.c();
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0020  */
    @Override // androidx.compose.ui.node.f0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k() {
        /*
            r5 = this;
            boolean r0 = r5.d
            androidx.compose.ui.platform.o0 r1 = r5.l
            if (r0 != 0) goto Le
            boolean r0 = r1.h()
            if (r0 != 0) goto Ld
            goto Le
        Ld:
            return
        Le:
            boolean r0 = r1.G()
            if (r0 == 0) goto L20
            androidx.compose.ui.platform.C0 r0 = r5.e
            boolean r2 = r0.g
            if (r2 == 0) goto L20
            r0.d()
            androidx.compose.ui.graphics.O r0 = r0.e
            goto L21
        L20:
            r0 = 0
        L21:
            androidx.compose.animation.h r2 = r5.b
            if (r2 == 0) goto L31
            androidx.compose.runtime.b0 r3 = new androidx.compose.runtime.b0
            r4 = 22
            r3.<init>(r2, r4)
            androidx.compose.ui.graphics.t r2 = r5.j
            r1.v(r2, r0, r3)
        L31:
            r0 = 0
            r5.l(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.K0.k():void");
    }

    public final void l(boolean z) {
        if (z != this.d) {
            this.d = z;
            this.a.s(this, z);
        }
    }
}
