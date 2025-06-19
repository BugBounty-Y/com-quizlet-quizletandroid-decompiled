package androidx.compose.ui.node;

import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G implements androidx.compose.ui.graphics.drawscope.d {
    public final androidx.compose.ui.graphics.drawscope.b a = new androidx.compose.ui.graphics.drawscope.b();
    public InterfaceC0919o b;

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void C(long j, long j2, long j3, float f, int i) {
        this.a.C(j, j2, j3, f, i);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void D(long j, float f, long j2, androidx.compose.ui.graphics.drawscope.e eVar) {
        this.a.D(j, f, j2, eVar);
    }

    @Override // androidx.compose.ui.unit.b
    public final long K(float f) {
        return this.a.K(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final float O(int i) {
        return this.a.O(i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float R(float f) {
        return f / this.a.a();
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.a.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a.a();
    }

    public final void b() {
        androidx.compose.ui.graphics.drawscope.b bVar = this.a;
        InterfaceC0858s interfaceC0858sO = bVar.b.o();
        InterfaceC0917m interfaceC0917m = this.b;
        Intrinsics.d(interfaceC0917m);
        androidx.compose.ui.p pVar = (androidx.compose.ui.p) interfaceC0917m;
        androidx.compose.ui.p pVarF = pVar.a.f;
        if (pVarF == null || (pVarF.d & 4) == 0) {
            pVarF = null;
        } else {
            while (pVarF != null) {
                int i = pVarF.c;
                if ((i & 2) != 0) {
                    break;
                } else if ((i & 4) != 0) {
                    break;
                } else {
                    pVarF = pVarF.f;
                }
            }
            pVarF = null;
        }
        if (pVarF == null) {
            a0 a0VarT = AbstractC0910f.t(interfaceC0917m, 4);
            if (a0VarT.W0() == pVar.a) {
                a0VarT = a0VarT.m;
                Intrinsics.d(a0VarT);
            }
            a0VarT.i1(interfaceC0858sO, (androidx.compose.ui.graphics.layer.b) bVar.b.c);
            return;
        }
        androidx.compose.runtime.collection.b bVar2 = null;
        while (pVarF != null) {
            if (pVarF instanceof InterfaceC0919o) {
                InterfaceC0919o interfaceC0919o = (InterfaceC0919o) pVarF;
                androidx.compose.ui.graphics.layer.b bVar3 = (androidx.compose.ui.graphics.layer.b) bVar.b.c;
                a0 a0VarT2 = AbstractC0910f.t(interfaceC0919o, 4);
                long jF = R5.f(a0VarT2.c);
                E e = a0VarT2.l;
                e.getClass();
                ((C0971v) H.a(e)).getSharedDrawScope().c(interfaceC0858sO, jF, a0VarT2, interfaceC0919o, bVar3);
            } else if ((pVarF.c & 4) != 0 && (pVarF instanceof AbstractC0918n)) {
                int i2 = 0;
                for (androidx.compose.ui.p pVar2 = ((AbstractC0918n) pVarF).o; pVar2 != null; pVar2 = pVar2.f) {
                    if ((pVar2.c & 4) != 0) {
                        i2++;
                        if (i2 == 1) {
                            pVarF = pVar2;
                        } else {
                            if (bVar2 == null) {
                                bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                            }
                            if (pVarF != null) {
                                bVar2.b(pVarF);
                                pVarF = null;
                            }
                            bVar2.b(pVar2);
                        }
                    }
                }
                if (i2 == 1) {
                }
            }
            pVarF = AbstractC0910f.f(bVar2);
        }
    }

    public final void c(InterfaceC0858s interfaceC0858s, long j, a0 a0Var, InterfaceC0919o interfaceC0919o, androidx.compose.ui.graphics.layer.b bVar) {
        InterfaceC0919o interfaceC0919o2 = this.b;
        this.b = interfaceC0919o;
        androidx.compose.ui.unit.k kVar = a0Var.l.s;
        androidx.compose.ui.graphics.drawscope.b bVar2 = this.a;
        com.quizlet.data.repository.folderset.c cVar = bVar2.b;
        androidx.compose.ui.graphics.drawscope.a aVar = ((androidx.compose.ui.graphics.drawscope.b) cVar.d).a;
        androidx.compose.ui.unit.b bVar3 = aVar.a;
        androidx.compose.ui.unit.k kVar2 = aVar.b;
        InterfaceC0858s interfaceC0858sO = cVar.o();
        com.quizlet.data.repository.folderset.c cVar2 = bVar2.b;
        long jR = cVar2.r();
        androidx.compose.ui.graphics.layer.b bVar4 = (androidx.compose.ui.graphics.layer.b) cVar2.c;
        cVar2.w(a0Var);
        cVar2.x(kVar);
        cVar2.v(interfaceC0858s);
        cVar2.y(j);
        cVar2.c = bVar;
        interfaceC0858s.e();
        try {
            interfaceC0919o.e(this);
            interfaceC0858s.q();
            cVar2.w(bVar3);
            cVar2.x(kVar2);
            cVar2.v(interfaceC0858sO);
            cVar2.y(jR);
            cVar2.c = bVar4;
            this.b = interfaceC0919o2;
        } catch (Throwable th) {
            interfaceC0858s.q();
            cVar2.w(bVar3);
            cVar2.x(kVar2);
            cVar2.v(interfaceC0858sO);
            cVar2.y(jR);
            cVar2.c = bVar4;
            throw th;
        }
    }

    @Override // androidx.compose.ui.unit.b
    public final float c0(float f) {
        return this.a.a() * f;
    }

    public final void d(AbstractC0857q abstractC0857q, long j, long j2, long j3, float f, androidx.compose.ui.graphics.drawscope.e eVar) {
        androidx.compose.ui.graphics.drawscope.b bVar = this.a;
        bVar.a.c.l(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.e.d(j2) + androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.e.b(j2) + androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.a.b(j3), androidx.compose.ui.geometry.a.c(j3), bVar.c(abstractC0857q, eVar, f, null, 3, 1));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final com.quizlet.data.repository.folderset.c e0() {
        return this.a.b;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void f0(long j, float f, float f2, long j2, long j3, float f3, androidx.compose.ui.graphics.drawscope.h hVar) {
        this.a.f0(j, f, f2, j2, j3, f3, hVar);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final long g() {
        return this.a.g();
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void g0(androidx.compose.ui.graphics.O o, long j, float f, androidx.compose.ui.graphics.drawscope.e eVar) {
        this.a.g0(o, j, f, eVar);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.a.a.b;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void h0(AbstractC0857q abstractC0857q, long j, long j2, float f, androidx.compose.ui.graphics.drawscope.e eVar, int i) {
        this.a.h0(abstractC0857q, j, j2, f, eVar, i);
    }

    @Override // androidx.compose.ui.unit.b
    public final int j0(long j) {
        return this.a.j0(j);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void l(C0848h c0848h, long j, long j2, long j3, float f, AbstractC0874w abstractC0874w, int i) {
        this.a.l(c0848h, j, j2, j3, f, abstractC0874w, i);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void l0(androidx.compose.ui.graphics.O o, AbstractC0857q abstractC0857q, float f, androidx.compose.ui.graphics.drawscope.e eVar, int i) {
        this.a.l0(o, abstractC0857q, f, eVar, i);
    }

    @Override // androidx.compose.ui.unit.b
    public final int m0(float f) {
        return this.a.m0(f);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final long o0() {
        return this.a.o0();
    }

    @Override // androidx.compose.ui.unit.b
    public final long q0(long j) {
        return this.a.q0(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return this.a.r(f);
    }

    @Override // androidx.compose.ui.unit.b
    public final long s(long j) {
        return this.a.s(j);
    }

    @Override // androidx.compose.ui.unit.b
    public final float v0(long j) {
        return this.a.v0(j);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void w(long j, long j2, long j3, long j4, androidx.compose.ui.graphics.drawscope.e eVar) {
        this.a.w(j, j2, j3, j4, eVar);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void w0(long j, long j2, long j3, float f, int i) {
        this.a.w0(j, j2, j3, f, i);
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        return this.a.y(j);
    }
}
