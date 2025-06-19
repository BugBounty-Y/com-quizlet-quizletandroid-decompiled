package androidx.compose.ui.graphics.drawscope;

import android.graphics.Paint;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.graphics.C0848h;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.O;
import androidx.compose.ui.graphics.X;
import androidx.compose.ui.node.G;
import com.google.android.gms.cloudmessaging.k;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public interface d extends androidx.compose.ui.unit.b {
    static /* synthetic */ void A(d dVar, O o, AbstractC0857q abstractC0857q, float f, h hVar, int i) {
        if ((i & 4) != 0) {
            f = 1.0f;
        }
        float f2 = f;
        e eVar = hVar;
        if ((i & 8) != 0) {
            eVar = g.a;
        }
        dVar.l0(o, abstractC0857q, f2, eVar, (i & 32) != 0 ? 3 : 0);
    }

    static /* synthetic */ void I(d dVar, long j, long j2, long j3, float f, int i) {
        if ((i & 2) != 0) {
            j2 = 0;
        }
        long j4 = j2;
        dVar.w0(j, j4, (i & 4) != 0 ? T(dVar.g(), j4) : j3, (i & 8) != 0 ? 1.0f : f, (i & 64) != 0 ? 3 : 0);
    }

    static /* synthetic */ void J(d dVar, AbstractC0857q abstractC0857q, long j, long j2, float f, e eVar, int i) {
        if ((i & 2) != 0) {
            j = 0;
        }
        long j3 = j;
        dVar.h0(abstractC0857q, j3, (i & 4) != 0 ? T(dVar.g(), j3) : j2, (i & 8) != 0 ? 1.0f : f, (i & 16) != 0 ? g.a : eVar, (i & 64) != 0 ? 3 : 6);
    }

    static void P(d dVar, C0848h c0848h, long j, long j2, float f, AbstractC0874w abstractC0874w, int i, int i2) {
        dVar.l(c0848h, 0L, j, (i2 & 16) != 0 ? j : j2, (i2 & 32) != 0 ? 1.0f : f, abstractC0874w, (i2 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? 1 : i);
    }

    static long T(long j, long j2) {
        return T4.a(androidx.compose.ui.geometry.e.d(j) - androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.e.b(j) - androidx.compose.ui.geometry.b.e(j2));
    }

    static /* synthetic */ void V(d dVar, long j, float f, long j2, e eVar, int i) {
        if ((i & 2) != 0) {
            f = androidx.compose.ui.geometry.e.c(dVar.g()) / 2.0f;
        }
        float f2 = f;
        if ((i & 4) != 0) {
            j2 = dVar.o0();
        }
        long j3 = j2;
        if ((i & 16) != 0) {
            eVar = g.a;
        }
        dVar.D(j, f2, j3, eVar);
    }

    static void Y(G g, AbstractC0857q abstractC0857q, long j, long j2, float f, float f2, int i) {
        if ((i & 64) != 0) {
            f2 = 1.0f;
        }
        b bVar = g.a;
        InterfaceC0858s interfaceC0858s = bVar.a.c;
        k kVarG = bVar.d;
        if (kVarG == null) {
            kVarG = F.g();
            kVarG.m(1);
            bVar.d = kVarG;
        }
        abstractC0857q.a(f2, bVar.g(), kVarG);
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
        if (kVarG.b() != 0) {
            kVarG.j(0);
        }
        if (kVarG.c() != 0) {
            kVarG.k(0);
        }
        if (!paint.isFilterBitmap()) {
            kVarG.h(1);
        }
        interfaceC0858s.h(j, j2, kVarG);
    }

    static /* synthetic */ void j(d dVar, O o, long j, float f, h hVar, int i) {
        if ((i & 4) != 0) {
            f = 1.0f;
        }
        float f2 = f;
        e eVar = hVar;
        if ((i & 8) != 0) {
            eVar = g.a;
        }
        dVar.g0(o, j, f2, eVar);
    }

    static void q(G g, X x, long j, long j2, long j3, e eVar, int i) {
        if ((i & 2) != 0) {
            j = 0;
        }
        long j4 = j;
        g.d(x, j4, (i & 4) != 0 ? T(g.a.g(), j4) : j2, j3, 1.0f, (i & 32) != 0 ? g.a : eVar);
    }

    static void z0(d dVar, long j, long j2, long j3, long j4, h hVar, int i) {
        long j5 = (i & 2) != 0 ? 0L : j2;
        dVar.w(j, j5, (i & 4) != 0 ? T(dVar.g(), j5) : j3, j4, (i & 16) != 0 ? g.a : hVar);
    }

    void C(long j, long j2, long j3, float f, int i);

    void D(long j, float f, long j2, e eVar);

    com.quizlet.data.repository.folderset.c e0();

    void f0(long j, float f, float f2, long j2, long j3, float f3, h hVar);

    default long g() {
        return e0().r();
    }

    void g0(O o, long j, float f, e eVar);

    androidx.compose.ui.unit.k getLayoutDirection();

    void h0(AbstractC0857q abstractC0857q, long j, long j2, float f, e eVar, int i);

    void l(C0848h c0848h, long j, long j2, long j3, float f, AbstractC0874w abstractC0874w, int i);

    void l0(O o, AbstractC0857q abstractC0857q, float f, e eVar, int i);

    default long o0() {
        return T4.c(e0().r());
    }

    void w(long j, long j2, long j3, long j4, e eVar);

    void w0(long j, long j2, long j3, float f, int i);
}
