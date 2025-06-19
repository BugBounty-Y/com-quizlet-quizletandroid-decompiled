package androidx.compose.foundation.text.input.internal;

import android.graphics.Rect;
import android.view.View;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.platform.AbstractC0955m0;
import androidx.compose.ui.platform.C0957n0;
import androidx.compose.ui.platform.Q0;
import androidx.compose.ui.text.H;
import androidx.compose.ui.text.K;
import java.lang.ref.WeakReference;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.W;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class g implements androidx.compose.ui.text.input.u {
    public w a;
    public y0 b;
    public B c;
    public d0 d;

    @Override // androidx.compose.ui.text.input.u
    public final void a() {
        j(null);
    }

    @Override // androidx.compose.ui.text.input.u
    public final void b() {
        Q0 q0;
        w wVar = this.a;
        if (wVar == null || (q0 = (Q0) AbstractC0910f.i(wVar, AbstractC0955m0.n)) == null) {
            return;
        }
        ((C0957n0) q0).b();
    }

    @Override // androidx.compose.ui.text.input.u
    public final void c(androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.s sVar, H h, androidx.camera.lifecycle.f fVar, androidx.compose.ui.geometry.c cVar, androidx.compose.ui.geometry.c cVar2) {
        B b = this.c;
        if (b != null) {
            y yVar = b.m;
            synchronized (yVar.c) {
                try {
                    yVar.j = a;
                    yVar.l = sVar;
                    yVar.k = h;
                    yVar.m = cVar;
                    yVar.n = cVar2;
                    if (yVar.e || yVar.d) {
                        yVar.a();
                    }
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
    }

    @Override // androidx.compose.ui.text.input.u
    public final void d() throws Throwable {
        y0 y0Var = this.b;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.b = null;
        W wI = i();
        if (wI != null) {
            ((d0) wI).g();
        }
    }

    @Override // androidx.compose.ui.text.input.u
    public final void e(androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.m mVar, androidx.activity.compose.g gVar, androidx.compose.foundation.text.D d) {
        j(new androidx.activity.compose.d(a, this, mVar, gVar, d, 2));
    }

    @Override // androidx.compose.ui.text.input.u
    public final void f() {
        Q0 q0;
        w wVar = this.a;
        if (wVar == null || (q0 = (Q0) AbstractC0910f.i(wVar, AbstractC0955m0.n)) == null) {
            return;
        }
        ((C0957n0) q0).a();
    }

    @Override // androidx.compose.ui.text.input.u
    public final void g(androidx.compose.ui.text.input.A a, androidx.compose.ui.text.input.A a2) {
        B b = this.c;
        if (b != null) {
            boolean z = (K.a(b.h.b, a2.b) && Intrinsics.b(b.h.c, a2.c)) ? false : true;
            b.h = a2;
            int size = b.j.size();
            for (int i = 0; i < size; i++) {
                D d = (D) ((WeakReference) b.j.get(i)).get();
                if (d != null) {
                    d.g = a2;
                }
            }
            y yVar = b.m;
            synchronized (yVar.c) {
                yVar.j = null;
                yVar.l = null;
                yVar.k = null;
                yVar.m = null;
                yVar.n = null;
                Unit unit = Unit.a;
            }
            if (Intrinsics.b(a, a2)) {
                if (z) {
                    u uVar = b.b;
                    int iE = K.e(a2.b);
                    int iD = K.d(a2.b);
                    K k = b.h.c;
                    int iE2 = k != null ? K.e(k.a) : -1;
                    K k2 = b.h.c;
                    uVar.i().updateSelection((View) uVar.b, iE, iD, iE2, k2 != null ? K.d(k2.a) : -1);
                    return;
                }
                return;
            }
            if (a != null && (!Intrinsics.b(a.a.a, a2.a.a) || (K.a(a.b, a2.b) && !Intrinsics.b(a.c, a2.c)))) {
                u uVar2 = b.b;
                uVar2.i().restartInput((View) uVar2.b);
                return;
            }
            int size2 = b.j.size();
            for (int i2 = 0; i2 < size2; i2++) {
                D d2 = (D) ((WeakReference) b.j.get(i2)).get();
                if (d2 != null) {
                    androidx.compose.ui.text.input.A a3 = b.h;
                    u uVar3 = b.b;
                    if (d2.k) {
                        d2.g = a3;
                        if (d2.i) {
                            uVar3.i().updateExtractedText((View) uVar3.b, d2.h, x.c(a3));
                        }
                        K k3 = a3.c;
                        int iE3 = k3 != null ? K.e(k3.a) : -1;
                        K k4 = a3.c;
                        int iD2 = k4 != null ? K.d(k4.a) : -1;
                        long j = a3.b;
                        uVar3.i().updateSelection((View) uVar3.b, K.e(j), K.d(j), iE3, iD2);
                    }
                }
            }
        }
    }

    @Override // androidx.compose.ui.text.input.u
    public final void h(androidx.compose.ui.geometry.c cVar) {
        Rect rect;
        B b = this.c;
        if (b != null) {
            b.l = new Rect(kotlin.math.c.b(cVar.a), kotlin.math.c.b(cVar.b), kotlin.math.c.b(cVar.c), kotlin.math.c.b(cVar.d));
            if (!b.j.isEmpty() || (rect = b.l) == null) {
                return;
            }
            b.a.requestRectangleOnScreen(new Rect(rect));
        }
    }

    public final W i() {
        d0 d0Var = this.d;
        if (d0Var != null) {
            return d0Var;
        }
        if (!androidx.compose.foundation.text.handwriting.e.a) {
            return null;
        }
        d0 d0VarB = e0.b(1, 0, kotlinx.coroutines.channels.a.c, 2);
        this.d = d0VarB;
        return d0VarB;
    }

    public final void j(androidx.activity.compose.d dVar) {
        w wVar = this.a;
        if (wVar == null) {
            return;
        }
        this.b = wVar.m ? kotlinx.coroutines.E.A(wVar.A0(), null, kotlinx.coroutines.D.d, new v(wVar, new C0500f(dVar, this, wVar, null), null), 1) : null;
    }

    public final void k(w wVar) {
        if (this.a == wVar) {
            this.a = null;
            return;
        }
        throw new IllegalStateException(("Expected textInputModifierNode to be " + wVar + " but was " + this.a).toString());
    }
}
