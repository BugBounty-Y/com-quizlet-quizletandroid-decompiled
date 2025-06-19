package androidx.compose.foundation;

import android.content.Context;
import android.os.Build;
import android.widget.EdgeEffect;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;

/* renamed from: androidx.compose.foundation.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0456n implements C0 {
    public androidx.compose.ui.geometry.b a;
    public final P b;
    public final InterfaceC0773a0 c;
    public final boolean d;
    public boolean e;
    public long f;
    public androidx.compose.ui.input.pointer.m g;
    public final androidx.compose.ui.q h;

    public C0456n(Context context, A0 a0) {
        P p = new P(context, androidx.compose.ui.graphics.F.A(a0.a));
        this.b = p;
        Unit unit = Unit.a;
        this.c = C0776c.y(unit, androidx.compose.runtime.V.c);
        this.d = true;
        this.f = 0L;
        this.h = androidx.compose.ui.input.pointer.v.a(androidx.compose.ui.n.b, unit, new C0454m(this, null)).g(Build.VERSION.SDK_INT >= 31 ? new O(this, p) : new O(this, p, a0));
    }

    @Override // androidx.compose.foundation.C0
    public final androidx.compose.ui.q a() {
        return this.h;
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x0061, code lost:
    
        if (r15.invokeSuspend(kotlin.Unit.a) == r1) goto L75;
     */
    /* JADX WARN: Removed duplicated region for block: B:101:0x01e1  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x020c  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0177  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0195  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x01c3  */
    @Override // androidx.compose.foundation.C0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(long r12, androidx.compose.foundation.gestures.J0 r14, kotlin.coroutines.h r15) {
        /*
            Method dump skipped, instructions count: 533
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0456n.b(long, androidx.compose.foundation.gestures.J0, kotlin.coroutines.h):java.lang.Object");
    }

    public final void c() {
        boolean zIsFinished;
        P p = this.b;
        EdgeEffect edgeEffect = p.d;
        if (edgeEffect != null) {
            edgeEffect.onRelease();
            zIsFinished = edgeEffect.isFinished();
        } else {
            zIsFinished = false;
        }
        EdgeEffect edgeEffect2 = p.e;
        if (edgeEffect2 != null) {
            edgeEffect2.onRelease();
            zIsFinished = edgeEffect2.isFinished() || zIsFinished;
        }
        EdgeEffect edgeEffect3 = p.f;
        if (edgeEffect3 != null) {
            edgeEffect3.onRelease();
            zIsFinished = edgeEffect3.isFinished() || zIsFinished;
        }
        EdgeEffect edgeEffect4 = p.g;
        if (edgeEffect4 != null) {
            edgeEffect4.onRelease();
            zIsFinished = edgeEffect4.isFinished() || zIsFinished;
        }
        if (zIsFinished) {
            g();
        }
    }

    @Override // androidx.compose.foundation.C0
    public final boolean d() {
        P p = this.b;
        EdgeEffect edgeEffect = p.d;
        C0458o c0458o = C0458o.a;
        if (edgeEffect != null) {
            if ((Build.VERSION.SDK_INT >= 31 ? c0458o.b(edgeEffect) : 0.0f) != DefinitionKt.NO_Float_VALUE) {
                return true;
            }
        }
        EdgeEffect edgeEffect2 = p.e;
        if (edgeEffect2 != null) {
            if ((Build.VERSION.SDK_INT >= 31 ? c0458o.b(edgeEffect2) : 0.0f) != DefinitionKt.NO_Float_VALUE) {
                return true;
            }
        }
        EdgeEffect edgeEffect3 = p.f;
        if (edgeEffect3 != null) {
            if ((Build.VERSION.SDK_INT >= 31 ? c0458o.b(edgeEffect3) : 0.0f) != DefinitionKt.NO_Float_VALUE) {
                return true;
            }
        }
        EdgeEffect edgeEffect4 = p.g;
        if (edgeEffect4 != null) {
            return (Build.VERSION.SDK_INT >= 31 ? c0458o.b(edgeEffect4) : 0.0f) != DefinitionKt.NO_Float_VALUE;
        }
        return false;
    }

    public final long e() {
        androidx.compose.ui.geometry.b bVar = this.a;
        long jC = bVar != null ? bVar.a : T4.c(this.f);
        return Q4.c(androidx.compose.ui.geometry.b.d(jC) / androidx.compose.ui.geometry.e.d(this.f), androidx.compose.ui.geometry.b.e(jC) / androidx.compose.ui.geometry.e.b(this.f));
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x0135  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x013a  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0149 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x014d  */
    @Override // androidx.compose.foundation.C0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long f(long r18, int r20, androidx.camera.lifecycle.f r21) {
        /*
            Method dump skipped, instructions count: 609
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0456n.f(long, int, androidx.camera.lifecycle.f):long");
    }

    public final void g() {
        if (this.d) {
            ((androidx.compose.runtime.L0) this.c).setValue(Unit.a);
        }
    }

    public final float h(long j) {
        float fD = androidx.compose.ui.geometry.b.d(e());
        float fE = androidx.compose.ui.geometry.b.e(j) / androidx.compose.ui.geometry.e.b(this.f);
        EdgeEffect edgeEffectB = this.b.b();
        float fC = -fE;
        float f = 1 - fD;
        int i = Build.VERSION.SDK_INT;
        C0458o c0458o = C0458o.a;
        if (i >= 31) {
            fC = c0458o.c(edgeEffectB, fC, f);
        } else {
            edgeEffectB.onPull(fC, f);
        }
        return (i >= 31 ? c0458o.b(edgeEffectB) : 0.0f) == DefinitionKt.NO_Float_VALUE ? androidx.compose.ui.geometry.e.b(this.f) * (-fC) : androidx.compose.ui.geometry.b.e(j);
    }

    public final float i(long j) {
        float fE = androidx.compose.ui.geometry.b.e(e());
        float fD = androidx.compose.ui.geometry.b.d(j) / androidx.compose.ui.geometry.e.d(this.f);
        EdgeEffect edgeEffectC = this.b.c();
        float f = 1 - fE;
        int i = Build.VERSION.SDK_INT;
        C0458o c0458o = C0458o.a;
        if (i >= 31) {
            fD = c0458o.c(edgeEffectC, fD, f);
        } else {
            edgeEffectC.onPull(fD, f);
        }
        return (i >= 31 ? c0458o.b(edgeEffectC) : 0.0f) == DefinitionKt.NO_Float_VALUE ? androidx.compose.ui.geometry.e.d(this.f) * fD : androidx.compose.ui.geometry.b.d(j);
    }

    public final float j(long j) {
        float fE = androidx.compose.ui.geometry.b.e(e());
        float fD = androidx.compose.ui.geometry.b.d(j) / androidx.compose.ui.geometry.e.d(this.f);
        EdgeEffect edgeEffectD = this.b.d();
        float fC = -fD;
        int i = Build.VERSION.SDK_INT;
        C0458o c0458o = C0458o.a;
        if (i >= 31) {
            fC = c0458o.c(edgeEffectD, fC, fE);
        } else {
            edgeEffectD.onPull(fC, fE);
        }
        return (i >= 31 ? c0458o.b(edgeEffectD) : 0.0f) == DefinitionKt.NO_Float_VALUE ? androidx.compose.ui.geometry.e.d(this.f) * (-fC) : androidx.compose.ui.geometry.b.d(j);
    }

    public final float k(long j) {
        float fD = androidx.compose.ui.geometry.b.d(e());
        float fE = androidx.compose.ui.geometry.b.e(j) / androidx.compose.ui.geometry.e.b(this.f);
        EdgeEffect edgeEffectE = this.b.e();
        int i = Build.VERSION.SDK_INT;
        C0458o c0458o = C0458o.a;
        if (i >= 31) {
            fE = c0458o.c(edgeEffectE, fE, fD);
        } else {
            edgeEffectE.onPull(fE, fD);
        }
        return (i >= 31 ? c0458o.b(edgeEffectE) : 0.0f) == DefinitionKt.NO_Float_VALUE ? androidx.compose.ui.geometry.e.b(this.f) * fE : androidx.compose.ui.geometry.b.e(j);
    }

    public final void l(long j) {
        boolean zA = androidx.compose.ui.geometry.e.a(this.f, 0L);
        boolean zA2 = androidx.compose.ui.geometry.e.a(j, this.f);
        this.f = j;
        if (!zA2) {
            long jA = R5.a(kotlin.math.c.b(androidx.compose.ui.geometry.e.d(j)), kotlin.math.c.b(androidx.compose.ui.geometry.e.b(j)));
            P p = this.b;
            p.c = jA;
            EdgeEffect edgeEffect = p.d;
            if (edgeEffect != null) {
                edgeEffect.setSize((int) (jA >> 32), (int) (jA & 4294967295L));
            }
            EdgeEffect edgeEffect2 = p.e;
            if (edgeEffect2 != null) {
                edgeEffect2.setSize((int) (jA >> 32), (int) (jA & 4294967295L));
            }
            EdgeEffect edgeEffect3 = p.f;
            if (edgeEffect3 != null) {
                edgeEffect3.setSize((int) (jA & 4294967295L), (int) (jA >> 32));
            }
            EdgeEffect edgeEffect4 = p.g;
            if (edgeEffect4 != null) {
                edgeEffect4.setSize((int) (jA & 4294967295L), (int) (jA >> 32));
            }
            EdgeEffect edgeEffect5 = p.h;
            if (edgeEffect5 != null) {
                edgeEffect5.setSize((int) (jA >> 32), (int) (jA & 4294967295L));
            }
            EdgeEffect edgeEffect6 = p.i;
            if (edgeEffect6 != null) {
                edgeEffect6.setSize((int) (jA >> 32), (int) (jA & 4294967295L));
            }
            EdgeEffect edgeEffect7 = p.j;
            if (edgeEffect7 != null) {
                edgeEffect7.setSize((int) (jA & 4294967295L), (int) (jA >> 32));
            }
            EdgeEffect edgeEffect8 = p.k;
            if (edgeEffect8 != null) {
                edgeEffect8.setSize((int) (jA & 4294967295L), (int) (jA >> 32));
            }
        }
        if (zA || zA2) {
            return;
        }
        g();
        c();
    }
}
