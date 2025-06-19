package androidx.compose.ui.text.platform;

import android.graphics.Paint;
import android.text.TextPaint;
import androidx.compose.runtime.E;
import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.U;
import com.google.android.gms.cloudmessaging.k;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends TextPaint {
    public k a;
    public androidx.compose.ui.text.style.j b;
    public int c;
    public U d;
    public AbstractC0857q e;
    public E f;
    public androidx.compose.ui.geometry.e g;
    public androidx.compose.ui.graphics.drawscope.e h;

    public final k a() {
        k kVar = this.a;
        if (kVar != null) {
            return kVar;
        }
        k kVar2 = new k(this);
        this.a = kVar2;
        return kVar2;
    }

    public final void b(int i) {
        if (i == this.c) {
            return;
        }
        a().e(i);
        this.c = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0038  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(androidx.compose.ui.graphics.AbstractC0857q r6, long r7, float r9) {
        /*
            r5 = this;
            r0 = 0
            if (r6 != 0) goto Ld
            r5.f = r0
            r5.e = r0
            r5.g = r0
            r5.setShader(r0)
            return
        Ld:
            boolean r1 = r6 instanceof androidx.compose.ui.graphics.X
            if (r1 == 0) goto L1d
            androidx.compose.ui.graphics.X r6 = (androidx.compose.ui.graphics.X) r6
            long r6 = r6.a
            long r6 = com.google.android.gms.internal.mlkit_vision_barcode.F5.c(r6, r9)
            r5.d(r6)
            return
        L1d:
            boolean r1 = r6 instanceof androidx.compose.ui.graphics.T
            if (r1 == 0) goto L6e
            androidx.compose.ui.graphics.q r1 = r5.e
            boolean r1 = kotlin.jvm.internal.Intrinsics.b(r1, r6)
            r2 = 0
            if (r1 == 0) goto L38
            androidx.compose.ui.geometry.e r1 = r5.g
            if (r1 != 0) goto L30
            r1 = r2
            goto L36
        L30:
            long r3 = r1.a
            boolean r1 = androidx.compose.ui.geometry.e.a(r3, r7)
        L36:
            if (r1 != 0) goto L59
        L38:
            r3 = 9205357640488583168(0x7fc000007fc00000, double:2.247117487993712E307)
            int r1 = (r7 > r3 ? 1 : (r7 == r3 ? 0 : -1))
            if (r1 == 0) goto L42
            r2 = 1
        L42:
            if (r2 == 0) goto L59
            r5.e = r6
            androidx.compose.ui.geometry.e r1 = new androidx.compose.ui.geometry.e
            r1.<init>(r7)
            r5.g = r1
            androidx.compose.material3.L0 r1 = new androidx.compose.material3.L0
            r2 = 2
            r1.<init>(r6, r7, r2)
            androidx.compose.runtime.E r6 = androidx.compose.runtime.C0776c.q(r1)
            r5.f = r6
        L59:
            com.google.android.gms.cloudmessaging.k r6 = r5.a()
            androidx.compose.runtime.E r7 = r5.f
            if (r7 == 0) goto L68
            java.lang.Object r7 = r7.getValue()
            r0 = r7
            android.graphics.Shader r0 = (android.graphics.Shader) r0
        L68:
            r6.i(r0)
            androidx.compose.ui.text.platform.i.b(r5, r9)
        L6e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.text.platform.d.c(androidx.compose.ui.graphics.q, long, float):void");
    }

    public final void d(long j) {
        if (j != 16) {
            setColor(F.A(j));
            this.f = null;
            this.e = null;
            this.g = null;
            setShader(null);
        }
    }

    public final void e(androidx.compose.ui.graphics.drawscope.e eVar) {
        if (eVar == null || Intrinsics.b(this.h, eVar)) {
            return;
        }
        this.h = eVar;
        if (eVar.equals(androidx.compose.ui.graphics.drawscope.g.a)) {
            setStyle(Paint.Style.FILL);
            return;
        }
        if (eVar instanceof androidx.compose.ui.graphics.drawscope.h) {
            a().m(1);
            androidx.compose.ui.graphics.drawscope.h hVar = (androidx.compose.ui.graphics.drawscope.h) eVar;
            a().l(hVar.a);
            ((Paint) a().c).setStrokeMiter(hVar.b);
            a().k(hVar.d);
            a().j(hVar.c);
            ((Paint) a().c).setPathEffect(null);
        }
    }

    public final void f(U u) {
        if (u == null || Intrinsics.b(this.d, u)) {
            return;
        }
        this.d = u;
        if (u.equals(U.d)) {
            clearShadowLayer();
            return;
        }
        U u2 = this.d;
        float f = u2.c;
        if (f == DefinitionKt.NO_Float_VALUE) {
            f = Float.MIN_VALUE;
        }
        setShadowLayer(f, androidx.compose.ui.geometry.b.d(u2.b), androidx.compose.ui.geometry.b.e(this.d.b), F.A(this.d.a));
    }

    public final void g(androidx.compose.ui.text.style.j jVar) {
        if (jVar == null || Intrinsics.b(this.b, jVar)) {
            return;
        }
        this.b = jVar;
        int i = jVar.a;
        setUnderlineText((i | 1) == i);
        androidx.compose.ui.text.style.j jVar2 = this.b;
        jVar2.getClass();
        int i2 = jVar2.a;
        setStrikeThruText((i2 | 2) == i2);
    }
}
