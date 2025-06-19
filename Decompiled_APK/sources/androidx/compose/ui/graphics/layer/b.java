package androidx.compose.ui.graphics.layer;

import android.graphics.Outline;
import android.graphics.Path;
import android.graphics.RectF;
import android.os.Build;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.C0850j;
import androidx.compose.ui.graphics.K;
import androidx.compose.ui.graphics.L;
import androidx.compose.ui.graphics.M;
import androidx.compose.ui.graphics.N;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b {
    public final d a;
    public Outline f;
    public float j;
    public N k;
    public C0850j l;
    public C0850j m;
    public boolean n;
    public com.google.android.gms.cloudmessaging.k o;
    public int p;
    public boolean r;
    public long s;
    public long t;
    public long u;
    public boolean v;
    public RectF w;
    public androidx.compose.ui.unit.b b = androidx.compose.ui.graphics.drawscope.c.a;
    public androidx.compose.ui.unit.k c = androidx.compose.ui.unit.k.a;
    public r d = a.b;
    public final C0775b0 e = new C0775b0(this, 12);
    public boolean g = true;
    public long h = 0;
    public long i = 9205357640488583168L;
    public final androidx.compose.material.ripple.r q = new androidx.compose.material.ripple.r();

    static {
        int i = j.a;
        int i2 = j.a;
    }

    public b(d dVar) {
        this.a = dVar;
        dVar.E(false);
        this.s = 0L;
        this.t = 0L;
        this.u = 9205357640488583168L;
    }

    public final void a() {
        Outline outline;
        if (this.g) {
            boolean z = this.v;
            d dVar = this.a;
            Outline outline2 = null;
            if (z || dVar.J() > DefinitionKt.NO_Float_VALUE) {
                C0850j c0850j = this.l;
                if (c0850j != null) {
                    RectF rectF = this.w;
                    if (rectF == null) {
                        rectF = new RectF();
                        this.w = rectF;
                    }
                    Path path = c0850j.a;
                    path.computeBounds(rectF, false);
                    int i = Build.VERSION.SDK_INT;
                    if (i > 28 || path.isConvex()) {
                        outline = this.f;
                        if (outline == null) {
                            outline = new Outline();
                            this.f = outline;
                        }
                        if (i >= 30) {
                            k.a.a(outline, c0850j);
                        } else {
                            outline.setConvexPath(path);
                        }
                        this.n = !outline.canClip();
                    } else {
                        Outline outline3 = this.f;
                        if (outline3 != null) {
                            outline3.setEmpty();
                        }
                        this.n = true;
                        outline = null;
                    }
                    this.l = c0850j;
                    if (outline != null) {
                        outline.setAlpha(dVar.a());
                        outline2 = outline;
                    }
                    dVar.r(outline2, R5.a(Math.round(rectF.width()), Math.round(rectF.height())));
                    if (this.n && this.v) {
                        dVar.E(false);
                        dVar.f();
                    } else {
                        dVar.E(this.v);
                    }
                } else {
                    dVar.E(this.v);
                    Outline outline4 = this.f;
                    if (outline4 == null) {
                        outline4 = new Outline();
                        this.f = outline4;
                    }
                    Outline outline5 = outline4;
                    long jF = R5.f(this.t);
                    long j = this.h;
                    long j2 = this.i;
                    long j3 = j2 == 9205357640488583168L ? jF : j2;
                    outline5.setRoundRect(Math.round(androidx.compose.ui.geometry.b.d(j)), Math.round(androidx.compose.ui.geometry.b.e(j)), Math.round(androidx.compose.ui.geometry.e.d(j3) + androidx.compose.ui.geometry.b.d(j)), Math.round(androidx.compose.ui.geometry.e.b(j3) + androidx.compose.ui.geometry.b.e(j)), this.j);
                    outline5.setAlpha(dVar.a());
                    dVar.r(outline5, (Math.round(androidx.compose.ui.geometry.e.d(j3)) << 32) | (Math.round(androidx.compose.ui.geometry.e.b(j3)) & 4294967295L));
                }
            } else {
                dVar.E(false);
                dVar.r(null, 0L);
            }
        }
        this.g = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x005c  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b() {
        /*
            r15 = this;
            boolean r0 = r15.r
            if (r0 == 0) goto L69
            int r0 = r15.p
            if (r0 != 0) goto L69
            androidx.compose.material.ripple.r r0 = r15.q
            java.lang.Object r1 = r0.b
            androidx.compose.ui.graphics.layer.b r1 = (androidx.compose.ui.graphics.layer.b) r1
            if (r1 == 0) goto L16
            r1.d()
            r1 = 0
            r0.b = r1
        L16:
            java.lang.Object r0 = r0.d
            androidx.collection.J r0 = (androidx.collection.J) r0
            if (r0 == 0) goto L64
            java.lang.Object[] r1 = r0.b
            long[] r2 = r0.a
            int r3 = r2.length
            int r3 = r3 + (-2)
            if (r3 < 0) goto L61
            r4 = 0
            r5 = r4
        L27:
            r6 = r2[r5]
            long r8 = ~r6
            r10 = 7
            long r8 = r8 << r10
            long r8 = r8 & r6
            r10 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r8 = r8 & r10
            int r8 = (r8 > r10 ? 1 : (r8 == r10 ? 0 : -1))
            if (r8 == 0) goto L5c
            int r8 = r5 - r3
            int r8 = ~r8
            int r8 = r8 >>> 31
            r9 = 8
            int r8 = 8 - r8
            r10 = r4
        L41:
            if (r10 >= r8) goto L5a
            r11 = 255(0xff, double:1.26E-321)
            long r11 = r11 & r6
            r13 = 128(0x80, double:6.3E-322)
            int r11 = (r11 > r13 ? 1 : (r11 == r13 ? 0 : -1))
            if (r11 >= 0) goto L56
            int r11 = r5 << 3
            int r11 = r11 + r10
            r11 = r1[r11]
            androidx.compose.ui.graphics.layer.b r11 = (androidx.compose.ui.graphics.layer.b) r11
            r11.d()
        L56:
            long r6 = r6 >> r9
            int r10 = r10 + 1
            goto L41
        L5a:
            if (r8 != r9) goto L61
        L5c:
            if (r5 == r3) goto L61
            int r5 = r5 + 1
            goto L27
        L61:
            r0.b()
        L64:
            androidx.compose.ui.graphics.layer.d r0 = r15.a
            r0.f()
        L69:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.layer.b.b():void");
    }

    public final N c() {
        N l;
        N n = this.k;
        C0850j c0850j = this.l;
        if (n != null) {
            return n;
        }
        if (c0850j != null) {
            K k = new K(c0850j);
            this.k = k;
            return k;
        }
        long jF = R5.f(this.t);
        long j = this.h;
        long j2 = this.i;
        if (j2 != 9205357640488583168L) {
            jF = j2;
        }
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fE = androidx.compose.ui.geometry.b.e(j);
        float fD2 = androidx.compose.ui.geometry.e.d(jF) + fD;
        float fB = androidx.compose.ui.geometry.e.b(jF) + fE;
        float f = this.j;
        if (f > DefinitionKt.NO_Float_VALUE) {
            long jA = O4.a(f, f);
            long jA2 = O4.a(androidx.compose.ui.geometry.a.b(jA), androidx.compose.ui.geometry.a.c(jA));
            l = new M(new androidx.compose.ui.geometry.d(fD, fE, fD2, fB, jA2, jA2, jA2, jA2));
        } else {
            l = new L(new androidx.compose.ui.geometry.c(fD, fE, fD2, fB));
        }
        this.k = l;
        return l;
    }

    public final void d() {
        this.p--;
        b();
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0094  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e() {
        /*
            r17 = this;
            r0 = r17
            r1 = 1
            androidx.compose.material.ripple.r r2 = r0.q
            java.lang.Object r3 = r2.b
            androidx.compose.ui.graphics.layer.b r3 = (androidx.compose.ui.graphics.layer.b) r3
            r2.c = r3
            java.lang.Object r3 = r2.d
            androidx.collection.J r3 = (androidx.collection.J) r3
            if (r3 == 0) goto L31
            boolean r4 = r3.h()
            if (r4 == 0) goto L31
            java.lang.Object r4 = r2.e
            androidx.collection.J r4 = (androidx.collection.J) r4
            if (r4 != 0) goto L26
            int r4 = androidx.collection.U.a
            androidx.collection.J r4 = new androidx.collection.J
            r4.<init>()
            r2.e = r4
        L26:
            java.lang.String r5 = "elements"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r3, r5)
            r4.i(r3)
            r3.b()
        L31:
            r2.a = r1
            androidx.compose.ui.unit.b r3 = r0.b
            androidx.compose.ui.unit.k r4 = r0.c
            androidx.compose.runtime.b0 r5 = r0.e
            androidx.compose.ui.graphics.layer.d r6 = r0.a
            r6.y(r3, r4, r0, r5)
            r3 = 0
            r2.a = r3
            java.lang.Object r4 = r2.c
            androidx.compose.ui.graphics.layer.b r4 = (androidx.compose.ui.graphics.layer.b) r4
            if (r4 == 0) goto L4a
            r4.d()
        L4a:
            java.lang.Object r2 = r2.e
            androidx.collection.J r2 = (androidx.collection.J) r2
            if (r2 == 0) goto L9b
            boolean r4 = r2.h()
            if (r4 == 0) goto L9b
            java.lang.Object[] r4 = r2.b
            long[] r5 = r2.a
            int r6 = r5.length
            int r6 = r6 + (-2)
            if (r6 < 0) goto L98
            r7 = r3
        L60:
            r8 = r5[r7]
            long r10 = ~r8
            r12 = 7
            long r10 = r10 << r12
            long r10 = r10 & r8
            r12 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r10 = r10 & r12
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 == 0) goto L94
            int r10 = r7 - r6
            int r10 = ~r10
            int r10 = r10 >>> 31
            r11 = 8
            int r10 = 8 - r10
            r12 = r3
        L7a:
            if (r12 >= r10) goto L92
            r13 = 255(0xff, double:1.26E-321)
            long r13 = r13 & r8
            r15 = 128(0x80, double:6.3E-322)
            int r13 = (r13 > r15 ? 1 : (r13 == r15 ? 0 : -1))
            if (r13 >= 0) goto L8f
            int r13 = r7 << 3
            int r13 = r13 + r12
            r13 = r4[r13]
            androidx.compose.ui.graphics.layer.b r13 = (androidx.compose.ui.graphics.layer.b) r13
            r13.d()
        L8f:
            long r8 = r8 >> r11
            int r12 = r12 + r1
            goto L7a
        L92:
            if (r10 != r11) goto L98
        L94:
            if (r7 == r6) goto L98
            int r7 = r7 + r1
            goto L60
        L98:
            r2.b()
        L9b:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.graphics.layer.b.e():void");
    }

    public final void f(float f) {
        d dVar = this.a;
        if (dVar.a() == f) {
            return;
        }
        dVar.i(f);
    }

    public final void g(long j, long j2, float f) {
        if (androidx.compose.ui.geometry.b.b(this.h, j) && androidx.compose.ui.geometry.e.a(this.i, j2) && this.j == f && this.l == null) {
            return;
        }
        this.k = null;
        this.l = null;
        this.g = true;
        this.n = false;
        this.h = j;
        this.i = j2;
        this.j = f;
        a();
    }
}
