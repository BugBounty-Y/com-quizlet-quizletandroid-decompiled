package androidx.compose.ui.graphics.drawscope;

import android.graphics.Paint;
import android.graphics.Shader;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.C0853m;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.O;
import com.google.android.gms.cloudmessaging.k;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements d {
    public final a a;
    public final com.quizlet.data.repository.folderset.c b;
    public k c;
    public k d;

    public b() {
        androidx.compose.ui.unit.c cVar = c.a;
        androidx.compose.ui.unit.k kVar = androidx.compose.ui.unit.k.a;
        f fVar = new f();
        a aVar = new a();
        aVar.a = cVar;
        aVar.b = kVar;
        aVar.c = fVar;
        aVar.d = 0L;
        this.a = aVar;
        this.b = new com.quizlet.data.repository.folderset.c(this);
    }

    public static k b(b bVar, long j, e eVar, float f, int i) {
        k kVarE = bVar.e(eVar);
        if (f != 1.0f) {
            j = C0861v.b(j, C0861v.d(j) * f);
        }
        if (!C0861v.c(F.c(((Paint) kVarE.c).getColor()), j)) {
            kVarE.f(j);
        }
        if (((Shader) kVarE.d) != null) {
            kVarE.i(null);
        }
        if (!Intrinsics.b((AbstractC0874w) kVarE.e, null)) {
            kVarE.g(null);
        }
        if (kVarE.b != i) {
            kVarE.e(i);
        }
        if (((Paint) kVarE.c).isFilterBitmap()) {
            return kVarE;
        }
        kVarE.h(1);
        return kVarE;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void C(long j, long j2, long j3, float f, int i) {
        InterfaceC0858s interfaceC0858s = this.a.c;
        k kVarG = this.d;
        if (kVarG == null) {
            kVarG = F.g();
            kVarG.m(1);
            this.d = kVarG;
        }
        if (!C0861v.c(F.c(((Paint) kVarG.c).getColor()), j)) {
            kVarG.f(j);
        }
        if (((Shader) kVarG.d) != null) {
            kVarG.i(null);
        }
        if (!Intrinsics.b((AbstractC0874w) kVarG.e, null)) {
            kVarG.g(null);
        }
        if (kVarG.b != 3) {
            kVarG.e(3);
        }
        Paint paint = (Paint) kVarG.c;
        if (paint.getStrokeWidth() != f) {
            kVarG.l(f);
        }
        if (paint.getStrokeMiter() != 4.0f) {
            ((Paint) kVarG.c).setStrokeMiter(4.0f);
        }
        if (kVarG.b() != i) {
            kVarG.j(i);
        }
        if (kVarG.c() != 0) {
            kVarG.k(0);
        }
        if (!paint.isFilterBitmap()) {
            kVarG.h(1);
        }
        interfaceC0858s.h(j2, j3, kVarG);
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void D(long j, float f, long j2, e eVar) {
        this.a.c.n(f, j2, b(this, j, eVar, 1.0f, 3));
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.a.a.Z();
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a.a.a();
    }

    public final k c(AbstractC0857q abstractC0857q, e eVar, float f, AbstractC0874w abstractC0874w, int i, int i2) {
        k kVarE = e(eVar);
        if (abstractC0857q != null) {
            abstractC0857q.a(f, g(), kVarE);
        } else {
            if (((Shader) kVarE.d) != null) {
                kVarE.i(null);
            }
            long jC = F.c(((Paint) kVarE.c).getColor());
            long j = C0861v.b;
            if (!C0861v.c(jC, j)) {
                kVarE.f(j);
            }
            if (((Paint) kVarE.c).getAlpha() / 255.0f != f) {
                kVarE.d(f);
            }
        }
        if (!Intrinsics.b((AbstractC0874w) kVarE.e, abstractC0874w)) {
            kVarE.g(abstractC0874w);
        }
        if (kVarE.b != i) {
            kVarE.e(i);
        }
        if (((Paint) kVarE.c).isFilterBitmap() == i2) {
            return kVarE;
        }
        kVarE.h(i2);
        return kVarE;
    }

    public final void d(C0848h c0848h, C0853m c0853m) {
        this.a.c.c(c0848h, c(null, g.a, 1.0f, c0853m, 3, 1));
    }

    public final k e(e eVar) {
        if (Intrinsics.b(eVar, g.a)) {
            k kVar = this.c;
            if (kVar != null) {
                return kVar;
            }
            k kVarG = F.g();
            kVarG.m(0);
            this.c = kVarG;
            return kVarG;
        }
        if (!(eVar instanceof h)) {
            throw new NoWhenBranchMatchedException();
        }
        k kVarG2 = this.d;
        if (kVarG2 == null) {
            kVarG2 = F.g();
            kVarG2.m(1);
            this.d = kVarG2;
        }
        Paint paint = (Paint) kVarG2.c;
        float strokeWidth = paint.getStrokeWidth();
        h hVar = (h) eVar;
        float f = hVar.a;
        if (strokeWidth != f) {
            kVarG2.l(f);
        }
        int iB = kVarG2.b();
        int i = hVar.c;
        if (iB != i) {
            kVarG2.j(i);
        }
        float strokeMiter = paint.getStrokeMiter();
        float f2 = hVar.b;
        if (strokeMiter != f2) {
            ((Paint) kVarG2.c).setStrokeMiter(f2);
        }
        int iC = kVarG2.c();
        int i2 = hVar.d;
        if (iC == i2) {
            return kVarG2;
        }
        kVarG2.k(i2);
        return kVarG2;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final com.quizlet.data.repository.folderset.c e0() {
        return this.b;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void f0(long j, float f, float f2, long j2, long j3, float f3, h hVar) {
        this.a.c.s(androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.b.e(j2), androidx.compose.ui.geometry.e.d(j3) + androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.e.b(j3) + androidx.compose.ui.geometry.b.e(j2), f, f2, b(this, j, hVar, f3, 3));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void g0(O o, long j, float f, e eVar) {
        this.a.c.d(o, b(this, j, eVar, f, 3));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final androidx.compose.ui.unit.k getLayoutDirection() {
        return this.a.b;
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void h0(AbstractC0857q abstractC0857q, long j, long j2, float f, e eVar, int i) {
        this.a.c.m(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.e.d(j2) + androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.e.b(j2) + androidx.compose.ui.geometry.b.e(j), c(abstractC0857q, eVar, f, null, i, 1));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void l(C0848h c0848h, long j, long j2, long j3, float f, AbstractC0874w abstractC0874w, int i) {
        this.a.c.r(c0848h, j, j2, j3, c(null, g.a, f, abstractC0874w, 3, i));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void l0(O o, AbstractC0857q abstractC0857q, float f, e eVar, int i) {
        this.a.c.d(o, c(abstractC0857q, eVar, f, null, i, 1));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void w(long j, long j2, long j3, long j4, e eVar) {
        this.a.c.l(androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.b.e(j2), androidx.compose.ui.geometry.e.d(j3) + androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.e.b(j3) + androidx.compose.ui.geometry.b.e(j2), androidx.compose.ui.geometry.a.b(j4), androidx.compose.ui.geometry.a.c(j4), b(this, j, eVar, 1.0f, 3));
    }

    @Override // androidx.compose.ui.graphics.drawscope.d
    public final void w0(long j, long j2, long j3, float f, int i) {
        g gVar = g.a;
        this.a.c.m(androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.b.e(j2), androidx.compose.ui.geometry.e.d(j3) + androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.e.b(j3) + androidx.compose.ui.geometry.b.e(j2), b(this, j, gVar, f, i));
    }
}
