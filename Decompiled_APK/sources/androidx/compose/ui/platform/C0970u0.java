package androidx.compose.ui.platform;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.Build;
import androidx.compose.animation.C0281h;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.google.android.gms.internal.mlkit_vision_barcode.U4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.u0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0970u0 implements androidx.compose.ui.node.f0 {
    public androidx.compose.ui.graphics.layer.b a;
    public final androidx.compose.ui.graphics.E b;
    public final C0971v c;
    public C0281h d;
    public androidx.compose.ui.input.nestedscroll.b e;
    public boolean g;
    public float[] i;
    public boolean j;
    public int n;
    public androidx.compose.ui.graphics.N p;
    public C0850j q;
    public com.google.android.gms.cloudmessaging.k r;
    public boolean s;
    public long f = R5.a(SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO);
    public final float[] h = androidx.compose.ui.graphics.J.a();
    public androidx.compose.ui.unit.b k = M5.b();
    public androidx.compose.ui.unit.k l = androidx.compose.ui.unit.k.a;
    public final androidx.compose.ui.graphics.drawscope.b m = new androidx.compose.ui.graphics.drawscope.b();
    public long o = androidx.compose.ui.graphics.Z.b;
    public final C0775b0 t = new C0775b0(this, 20);

    public C0970u0(androidx.compose.ui.graphics.layer.b bVar, androidx.compose.ui.graphics.E e, C0971v c0971v, C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar2) {
        this.a = bVar;
        this.b = e;
        this.c = c0971v;
        this.d = c0281h;
        this.e = bVar2;
    }

    @Override // androidx.compose.ui.node.f0
    public final void a(C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar) {
        androidx.compose.ui.graphics.E e = this.b;
        if (e == null) {
            throw new IllegalArgumentException("currently reuse is only supported when we manage the layer lifecycle");
        }
        if (!this.a.r) {
            throw new IllegalArgumentException("layer should have been released before reuse");
        }
        this.a = e.b();
        this.g = false;
        this.d = c0281h;
        this.e = bVar;
        this.o = androidx.compose.ui.graphics.Z.b;
        this.s = false;
        this.f = R5.a(SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        this.p = null;
        this.n = 0;
    }

    @Override // androidx.compose.ui.node.f0
    public final void b(float[] fArr) {
        androidx.compose.ui.graphics.J.g(fArr, m());
    }

    @Override // androidx.compose.ui.node.f0
    public final boolean c(long j) {
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fE = androidx.compose.ui.geometry.b.e(j);
        androidx.compose.ui.graphics.layer.b bVar = this.a;
        if (bVar.v) {
            return N.z(bVar.c(), fD, fE);
        }
        return true;
    }

    @Override // androidx.compose.ui.node.f0
    public final void d(androidx.compose.ui.graphics.S s) {
        androidx.compose.ui.input.nestedscroll.b bVar;
        int i;
        androidx.compose.ui.input.nestedscroll.b bVar2;
        int i2 = s.a | this.n;
        this.l = s.t;
        this.k = s.s;
        int i3 = i2 & 4096;
        if (i3 != 0) {
            this.o = s.n;
        }
        if ((i2 & 1) != 0) {
            androidx.compose.ui.graphics.layer.b bVar3 = this.a;
            float f = s.b;
            androidx.compose.ui.graphics.layer.d dVar = bVar3.a;
            if (dVar.o() != f) {
                dVar.j(f);
            }
        }
        if ((i2 & 2) != 0) {
            androidx.compose.ui.graphics.layer.b bVar4 = this.a;
            float f2 = s.c;
            androidx.compose.ui.graphics.layer.d dVar2 = bVar4.a;
            if (dVar2.K() != f2) {
                dVar2.g(f2);
            }
        }
        if ((i2 & 4) != 0) {
            this.a.f(s.d);
        }
        if ((i2 & 8) != 0) {
            androidx.compose.ui.graphics.layer.b bVar5 = this.a;
            float f3 = s.e;
            androidx.compose.ui.graphics.layer.d dVar3 = bVar5.a;
            if (dVar3.D() != f3) {
                dVar3.k(f3);
            }
        }
        if ((i2 & 16) != 0) {
            androidx.compose.ui.graphics.layer.b bVar6 = this.a;
            float f4 = s.f;
            androidx.compose.ui.graphics.layer.d dVar4 = bVar6.a;
            if (dVar4.z() != f4) {
                dVar4.e(f4);
            }
        }
        boolean z = true;
        if ((i2 & 32) != 0) {
            androidx.compose.ui.graphics.layer.b bVar7 = this.a;
            float f5 = s.g;
            androidx.compose.ui.graphics.layer.d dVar5 = bVar7.a;
            if (dVar5.J() != f5) {
                dVar5.p(f5);
                bVar7.g = true;
                bVar7.a();
            }
            if (s.g > DefinitionKt.NO_Float_VALUE && !this.s && (bVar2 = this.e) != null) {
                bVar2.invoke();
            }
        }
        if ((i2 & 64) != 0) {
            androidx.compose.ui.graphics.layer.b bVar8 = this.a;
            long j = s.h;
            androidx.compose.ui.graphics.layer.d dVar6 = bVar8.a;
            if (!C0861v.c(j, dVar6.x())) {
                dVar6.B(j);
            }
        }
        if ((i2 & 128) != 0) {
            androidx.compose.ui.graphics.layer.b bVar9 = this.a;
            long j2 = s.i;
            androidx.compose.ui.graphics.layer.d dVar7 = bVar9.a;
            if (!C0861v.c(j2, dVar7.A())) {
                dVar7.H(j2);
            }
        }
        if ((i2 & 1024) != 0) {
            androidx.compose.ui.graphics.layer.b bVar10 = this.a;
            float f6 = s.l;
            androidx.compose.ui.graphics.layer.d dVar8 = bVar10.a;
            if (dVar8.v() != f6) {
                dVar8.d(f6);
            }
        }
        if ((i2 & 256) != 0) {
            androidx.compose.ui.graphics.layer.b bVar11 = this.a;
            float f7 = s.j;
            androidx.compose.ui.graphics.layer.d dVar9 = bVar11.a;
            if (dVar9.F() != f7) {
                dVar9.n(f7);
            }
        }
        if ((i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0) {
            androidx.compose.ui.graphics.layer.b bVar12 = this.a;
            float f8 = s.k;
            androidx.compose.ui.graphics.layer.d dVar10 = bVar12.a;
            if (dVar10.u() != f8) {
                dVar10.c(f8);
            }
        }
        if ((i2 & 2048) != 0) {
            androidx.compose.ui.graphics.layer.b bVar13 = this.a;
            float f9 = s.m;
            androidx.compose.ui.graphics.layer.d dVar11 = bVar13.a;
            if (dVar11.C() != f9) {
                dVar11.l(f9);
            }
        }
        if (i3 != 0) {
            if (androidx.compose.ui.graphics.Z.a(this.o, androidx.compose.ui.graphics.Z.b)) {
                androidx.compose.ui.graphics.layer.b bVar14 = this.a;
                if (!androidx.compose.ui.geometry.b.b(bVar14.u, 9205357640488583168L)) {
                    bVar14.u = 9205357640488583168L;
                    bVar14.a.w(9205357640488583168L);
                }
            } else {
                androidx.compose.ui.graphics.layer.b bVar15 = this.a;
                long jC = Q4.c(androidx.compose.ui.graphics.Z.b(this.o) * ((int) (this.f >> 32)), androidx.compose.ui.graphics.Z.c(this.o) * ((int) (this.f & 4294967295L)));
                if (!androidx.compose.ui.geometry.b.b(bVar15.u, jC)) {
                    bVar15.u = jC;
                    bVar15.a.w(jC);
                }
            }
        }
        if ((i2 & 16384) != 0) {
            androidx.compose.ui.graphics.layer.b bVar16 = this.a;
            boolean z2 = s.p;
            if (bVar16.v != z2) {
                bVar16.v = z2;
                bVar16.g = true;
                bVar16.a();
            }
        }
        if ((131072 & i2) != 0) {
            androidx.compose.ui.graphics.layer.b bVar17 = this.a;
            C0856p c0856p = s.u;
            androidx.compose.ui.graphics.layer.d dVar12 = bVar17.a;
            if (!Intrinsics.b(dVar12.q(), c0856p)) {
                dVar12.m(c0856p);
            }
        }
        if ((32768 & i2) != 0) {
            androidx.compose.ui.graphics.layer.b bVar18 = this.a;
            int i4 = s.q;
            if (i4 == 0) {
                i = 0;
            } else if (i4 == 1) {
                i = 1;
            } else {
                i = 2;
                if (i4 != 2) {
                    throw new IllegalStateException("Not supported composition strategy");
                }
            }
            androidx.compose.ui.graphics.layer.d dVar13 = bVar18.a;
            if (dVar13.s() != i) {
                dVar13.G(i);
            }
        }
        if (Intrinsics.b(this.p, s.v)) {
            z = false;
        } else {
            androidx.compose.ui.graphics.N n = s.v;
            this.p = n;
            if (n != null) {
                androidx.compose.ui.graphics.layer.b bVar19 = this.a;
                if (n instanceof androidx.compose.ui.graphics.L) {
                    androidx.compose.ui.geometry.c cVar = ((androidx.compose.ui.graphics.L) n).a;
                    bVar19.g(Q4.c(cVar.a, cVar.b), T4.a(cVar.e(), cVar.d()), DefinitionKt.NO_Float_VALUE);
                } else if (n instanceof androidx.compose.ui.graphics.K) {
                    bVar19.k = null;
                    bVar19.i = 9205357640488583168L;
                    bVar19.h = 0L;
                    bVar19.j = DefinitionKt.NO_Float_VALUE;
                    bVar19.g = true;
                    bVar19.n = false;
                    bVar19.l = ((androidx.compose.ui.graphics.K) n).a;
                    bVar19.a();
                } else if (n instanceof androidx.compose.ui.graphics.M) {
                    androidx.compose.ui.graphics.M m = (androidx.compose.ui.graphics.M) n;
                    C0850j c0850j = m.b;
                    if (c0850j != null) {
                        bVar19.k = null;
                        bVar19.i = 9205357640488583168L;
                        bVar19.h = 0L;
                        bVar19.j = DefinitionKt.NO_Float_VALUE;
                        bVar19.g = true;
                        bVar19.n = false;
                        bVar19.l = c0850j;
                        bVar19.a();
                    } else {
                        androidx.compose.ui.geometry.d dVar14 = m.a;
                        bVar19.g(Q4.c(dVar14.a, dVar14.b), T4.a(dVar14.b(), dVar14.a()), androidx.compose.ui.geometry.a.b(dVar14.h));
                    }
                }
                if ((n instanceof androidx.compose.ui.graphics.K) && Build.VERSION.SDK_INT < 33 && (bVar = this.e) != null) {
                    bVar.invoke();
                }
            }
        }
        this.n = s.a;
        if (i2 != 0 || z) {
            u1.a.a(this.c);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void destroy() {
        this.d = null;
        this.e = null;
        this.g = true;
        boolean z = this.j;
        C0971v c0971v = this.c;
        if (z) {
            this.j = false;
            c0971v.s(this, false);
        }
        androidx.compose.ui.graphics.E e = this.b;
        if (e != null) {
            e.a(this.a);
            c0971v.A(this);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final long e(long j, boolean z) {
        if (!z) {
            return androidx.compose.ui.graphics.J.b(j, m());
        }
        float[] fArrL = l();
        if (fArrL != null) {
            return androidx.compose.ui.graphics.J.b(j, fArrL);
        }
        return 9187343241974906880L;
    }

    @Override // androidx.compose.ui.node.f0
    public final void f(long j) {
        if (androidx.compose.ui.unit.j.a(j, this.f)) {
            return;
        }
        this.f = j;
        if (this.j || this.g) {
            return;
        }
        C0971v c0971v = this.c;
        c0971v.invalidate();
        if (true != this.j) {
            this.j = true;
            c0971v.s(this, true);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void g(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        float f;
        Canvas canvasA = AbstractC0845e.a(interfaceC0858s);
        if (canvasA.isHardwareAccelerated()) {
            k();
            this.s = this.a.a.J() > DefinitionKt.NO_Float_VALUE;
            androidx.compose.ui.graphics.drawscope.b bVar2 = this.m;
            com.quizlet.data.repository.folderset.c cVar = bVar2.b;
            cVar.v(interfaceC0858s);
            cVar.c = bVar;
            U4.a(bVar2, this.a);
            return;
        }
        androidx.compose.ui.graphics.layer.b bVar3 = this.a;
        long j = bVar3.s;
        float f2 = (int) (j >> 32);
        float f3 = (int) (j & 4294967295L);
        long j2 = this.f;
        float f4 = f2 + ((int) (j2 >> 32));
        float f5 = ((int) (4294967295L & j2)) + f3;
        if (bVar3.a.a() < 1.0f) {
            com.google.android.gms.cloudmessaging.k kVarG = this.r;
            if (kVarG == null) {
                kVarG = androidx.compose.ui.graphics.F.g();
                this.r = kVarG;
            }
            kVarG.d(this.a.a.a());
            f = f2;
            canvasA.saveLayer(f, f3, f4, f5, (Paint) kVarG.c);
        } else {
            f = f2;
            interfaceC0858s.e();
        }
        interfaceC0858s.p(f, f3);
        interfaceC0858s.j(m());
        androidx.compose.ui.graphics.layer.b bVar4 = this.a;
        boolean z = bVar4.v;
        if (z && z) {
            androidx.compose.ui.graphics.N nC = bVar4.c();
            if (nC instanceof androidx.compose.ui.graphics.L) {
                InterfaceC0858s.k(interfaceC0858s, ((androidx.compose.ui.graphics.L) nC).a);
            } else if (nC instanceof androidx.compose.ui.graphics.M) {
                C0850j c0850jH = this.q;
                if (c0850jH == null) {
                    c0850jH = androidx.compose.ui.graphics.F.h();
                    this.q = c0850jH;
                }
                c0850jH.e();
                androidx.compose.ui.graphics.O.b(c0850jH, ((androidx.compose.ui.graphics.M) nC).a);
                interfaceC0858s.i(c0850jH);
            } else if (nC instanceof androidx.compose.ui.graphics.K) {
                interfaceC0858s.i(((androidx.compose.ui.graphics.K) nC).a);
            }
        }
        C0281h c0281h = this.d;
        if (c0281h != null) {
            c0281h.invoke(interfaceC0858s, null);
        }
        interfaceC0858s.q();
    }

    @Override // androidx.compose.ui.node.f0
    public final void h(float[] fArr) {
        float[] fArrL = l();
        if (fArrL != null) {
            androidx.compose.ui.graphics.J.g(fArr, fArrL);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void i(androidx.camera.camera2.internal.q0 q0Var, boolean z) {
        if (!z) {
            androidx.compose.ui.graphics.J.c(m(), q0Var);
            return;
        }
        float[] fArrL = l();
        if (fArrL != null) {
            androidx.compose.ui.graphics.J.c(fArrL, q0Var);
            return;
        }
        q0Var.b = DefinitionKt.NO_Float_VALUE;
        q0Var.c = DefinitionKt.NO_Float_VALUE;
        q0Var.d = DefinitionKt.NO_Float_VALUE;
        q0Var.e = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.compose.ui.node.f0
    public final void invalidate() {
        if (this.j || this.g) {
            return;
        }
        C0971v c0971v = this.c;
        c0971v.invalidate();
        if (true != this.j) {
            this.j = true;
            c0971v.s(this, true);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void j(long j) {
        androidx.compose.ui.graphics.layer.b bVar = this.a;
        if (!androidx.compose.ui.unit.h.b(bVar.s, j)) {
            bVar.s = j;
            long j2 = bVar.t;
            bVar.a.t((int) (j >> 32), (int) (j & 4294967295L), j2);
        }
        u1.a.a(this.c);
    }

    @Override // androidx.compose.ui.node.f0
    public final void k() {
        if (this.j) {
            if (!androidx.compose.ui.graphics.Z.a(this.o, androidx.compose.ui.graphics.Z.b) && !androidx.compose.ui.unit.j.a(this.a.t, this.f)) {
                androidx.compose.ui.graphics.layer.b bVar = this.a;
                long jC = Q4.c(androidx.compose.ui.graphics.Z.b(this.o) * ((int) (this.f >> 32)), androidx.compose.ui.graphics.Z.c(this.o) * ((int) (this.f & 4294967295L)));
                if (!androidx.compose.ui.geometry.b.b(bVar.u, jC)) {
                    bVar.u = jC;
                    bVar.a.w(jC);
                }
            }
            androidx.compose.ui.graphics.layer.b bVar2 = this.a;
            androidx.compose.ui.unit.b bVar3 = this.k;
            androidx.compose.ui.unit.k kVar = this.l;
            long j = this.f;
            if (!androidx.compose.ui.unit.j.a(bVar2.t, j)) {
                bVar2.t = j;
                long j2 = bVar2.s;
                bVar2.a.t((int) (j2 >> 32), (int) (4294967295L & j2), j);
                if (bVar2.i == 9205357640488583168L) {
                    bVar2.g = true;
                    bVar2.a();
                }
            }
            bVar2.b = bVar3;
            bVar2.c = kVar;
            bVar2.d = this.t;
            bVar2.e();
            if (this.j) {
                this.j = false;
                this.c.s(this, false);
            }
        }
    }

    public final float[] l() {
        float[] fArrM = m();
        float[] fArrA = this.i;
        if (fArrA == null) {
            fArrA = androidx.compose.ui.graphics.J.a();
            this.i = fArrA;
        }
        if (N.x(fArrM, fArrA)) {
            return fArrA;
        }
        return null;
    }

    public final float[] m() {
        androidx.compose.ui.graphics.layer.b bVar = this.a;
        long jC = Q4.i(bVar.u) ? T4.c(R5.f(this.f)) : bVar.u;
        float[] fArr = this.h;
        androidx.compose.ui.graphics.J.d(fArr);
        float[] fArrA = androidx.compose.ui.graphics.J.a();
        androidx.compose.ui.graphics.J.h(fArrA, -androidx.compose.ui.geometry.b.d(jC), -androidx.compose.ui.geometry.b.e(jC));
        androidx.compose.ui.graphics.J.g(fArr, fArrA);
        float[] fArrA2 = androidx.compose.ui.graphics.J.a();
        androidx.compose.ui.graphics.layer.d dVar = bVar.a;
        androidx.compose.ui.graphics.J.h(fArrA2, dVar.D(), dVar.z());
        double dF = (dVar.F() * 3.141592653589793d) / 180.0d;
        float fCos = (float) Math.cos(dF);
        float fSin = (float) Math.sin(dF);
        float f = fArrA2[1];
        float f2 = fArrA2[2];
        float f3 = fArrA2[5];
        float f4 = fArrA2[6];
        float f5 = fArrA2[9];
        float f6 = fArrA2[10];
        float f7 = fArrA2[13];
        float f8 = fArrA2[14];
        fArrA2[1] = (f * fCos) - (f2 * fSin);
        fArrA2[2] = (f2 * fCos) + (f * fSin);
        fArrA2[5] = (f3 * fCos) - (f4 * fSin);
        fArrA2[6] = (f4 * fCos) + (f3 * fSin);
        fArrA2[9] = (f5 * fCos) - (f6 * fSin);
        fArrA2[10] = (f6 * fCos) + (f5 * fSin);
        fArrA2[13] = (f7 * fCos) - (f8 * fSin);
        fArrA2[14] = (f8 * fCos) + (f7 * fSin);
        double dU = (dVar.u() * 3.141592653589793d) / 180.0d;
        float fCos2 = (float) Math.cos(dU);
        float fSin2 = (float) Math.sin(dU);
        float f9 = fArrA2[0];
        float f10 = fArrA2[2];
        float f11 = fArrA2[4];
        float f12 = fArrA2[6];
        float f13 = fArrA2[8];
        float f14 = fArrA2[10];
        float f15 = fArrA2[12];
        float f16 = fArrA2[14];
        fArrA2[0] = (f10 * fSin2) + (f9 * fCos2);
        fArrA2[2] = (f10 * fCos2) + ((-f9) * fSin2);
        fArrA2[4] = (f12 * fSin2) + (f11 * fCos2);
        fArrA2[6] = (f12 * fCos2) + ((-f11) * fSin2);
        fArrA2[8] = (f14 * fSin2) + (f13 * fCos2);
        fArrA2[10] = (f14 * fCos2) + ((-f13) * fSin2);
        fArrA2[12] = (f16 * fSin2) + (f15 * fCos2);
        fArrA2[14] = (f16 * fCos2) + ((-f15) * fSin2);
        androidx.compose.ui.graphics.J.e(dVar.v(), fArrA2);
        androidx.compose.ui.graphics.J.f(fArrA2, dVar.o(), dVar.K());
        androidx.compose.ui.graphics.J.g(fArr, fArrA2);
        float[] fArrA3 = androidx.compose.ui.graphics.J.a();
        androidx.compose.ui.graphics.J.h(fArrA3, androidx.compose.ui.geometry.b.d(jC), androidx.compose.ui.geometry.b.e(jC));
        androidx.compose.ui.graphics.J.g(fArr, fArrA3);
        return fArr;
    }
}
