package androidx.compose.ui.platform;

import android.graphics.Outline;
import android.os.Build;
import androidx.compose.ui.graphics.C0850j;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.S4;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C0 {
    public boolean a = true;
    public final Outline b;
    public androidx.compose.ui.graphics.N c;
    public C0850j d;
    public androidx.compose.ui.graphics.O e;
    public boolean f;
    public boolean g;
    public androidx.compose.ui.graphics.O h;
    public androidx.compose.ui.geometry.d i;
    public float j;
    public long k;
    public long l;
    public boolean m;

    public C0() {
        Outline outline = new Outline();
        outline.setAlpha(1.0f);
        this.b = outline;
        this.k = 0L;
        this.l = 0L;
    }

    /* JADX WARN: Removed duplicated region for block: B:26:0x0066  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(androidx.compose.ui.graphics.InterfaceC0858s r20) {
        /*
            r19 = this;
            r0 = r19
            r1 = r20
            r0.d()
            androidx.compose.ui.graphics.O r2 = r0.e
            if (r2 == 0) goto Lf
            r1.i(r2)
            return
        Lf:
            float r2 = r0.j
            r3 = 0
            int r3 = (r2 > r3 ? 1 : (r2 == r3 ? 0 : -1))
            if (r3 <= 0) goto Lc1
            androidx.compose.ui.graphics.O r3 = r0.h
            androidx.compose.ui.geometry.d r4 = r0.i
            if (r3 == 0) goto L66
            long r5 = r0.k
            long r7 = r0.l
            if (r4 == 0) goto L66
            boolean r9 = com.google.android.gms.internal.mlkit_vision_barcode.S4.g(r4)
            if (r9 != 0) goto L29
            goto L66
        L29:
            float r9 = androidx.compose.ui.geometry.b.d(r5)
            float r10 = r4.a
            int r9 = (r10 > r9 ? 1 : (r10 == r9 ? 0 : -1))
            if (r9 != 0) goto L66
            float r9 = androidx.compose.ui.geometry.b.e(r5)
            float r10 = r4.b
            int r9 = (r10 > r9 ? 1 : (r10 == r9 ? 0 : -1))
            if (r9 != 0) goto L66
            float r9 = androidx.compose.ui.geometry.b.d(r5)
            float r10 = androidx.compose.ui.geometry.e.d(r7)
            float r10 = r10 + r9
            float r9 = r4.c
            int r9 = (r9 > r10 ? 1 : (r9 == r10 ? 0 : -1))
            if (r9 != 0) goto L66
            float r5 = androidx.compose.ui.geometry.b.e(r5)
            float r6 = androidx.compose.ui.geometry.e.b(r7)
            float r6 = r6 + r5
            float r5 = r4.d
            int r5 = (r5 > r6 ? 1 : (r5 == r6 ? 0 : -1))
            if (r5 != 0) goto L66
            long r4 = r4.e
            float r4 = androidx.compose.ui.geometry.a.b(r4)
            int r2 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r2 != 0) goto L66
            goto Lbd
        L66:
            long r4 = r0.k
            float r7 = androidx.compose.ui.geometry.b.d(r4)
            long r4 = r0.k
            float r8 = androidx.compose.ui.geometry.b.e(r4)
            long r4 = r0.k
            float r2 = androidx.compose.ui.geometry.b.d(r4)
            long r4 = r0.l
            float r4 = androidx.compose.ui.geometry.e.d(r4)
            float r9 = r4 + r2
            long r4 = r0.k
            float r2 = androidx.compose.ui.geometry.b.e(r4)
            long r4 = r0.l
            float r4 = androidx.compose.ui.geometry.e.b(r4)
            float r10 = r4 + r2
            float r2 = r0.j
            long r4 = com.google.android.gms.internal.mlkit_vision_barcode.O4.a(r2, r2)
            float r2 = androidx.compose.ui.geometry.a.b(r4)
            float r4 = androidx.compose.ui.geometry.a.c(r4)
            long r11 = com.google.android.gms.internal.mlkit_vision_barcode.O4.a(r2, r4)
            androidx.compose.ui.geometry.d r6 = new androidx.compose.ui.geometry.d
            r13 = r11
            r15 = r11
            r17 = r11
            r6.<init>(r7, r8, r9, r10, r11, r13, r15, r17)
            if (r3 != 0) goto Lb0
            androidx.compose.ui.graphics.j r3 = androidx.compose.ui.graphics.F.h()
            goto Lb6
        Lb0:
            r2 = r3
            androidx.compose.ui.graphics.j r2 = (androidx.compose.ui.graphics.C0850j) r2
            r2.e()
        Lb6:
            androidx.compose.ui.graphics.O.b(r3, r6)
            r0.i = r6
            r0.h = r3
        Lbd:
            r1.i(r3)
            return
        Lc1:
            long r2 = r0.k
            float r2 = androidx.compose.ui.geometry.b.d(r2)
            long r3 = r0.k
            float r3 = androidx.compose.ui.geometry.b.e(r3)
            long r4 = r0.k
            float r4 = androidx.compose.ui.geometry.b.d(r4)
            long r5 = r0.l
            float r5 = androidx.compose.ui.geometry.e.d(r5)
            float r4 = r4 + r5
            long r5 = r0.k
            float r5 = androidx.compose.ui.geometry.b.e(r5)
            long r6 = r0.l
            float r6 = androidx.compose.ui.geometry.e.b(r6)
            float r5 = r5 + r6
            r6 = 1
            r1.o(r2, r3, r4, r5, r6)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0.a(androidx.compose.ui.graphics.s):void");
    }

    public final Outline b() {
        d();
        if (this.m && this.a) {
            return this.b;
        }
        return null;
    }

    public final boolean c(androidx.compose.ui.graphics.N n, float f, boolean z, float f2, long j) {
        this.b.setAlpha(f);
        boolean zB = Intrinsics.b(this.c, n);
        boolean z2 = !zB;
        if (!zB) {
            this.c = n;
            this.f = true;
        }
        this.l = j;
        boolean z3 = n != null && (z || f2 > DefinitionKt.NO_Float_VALUE);
        if (this.m != z3) {
            this.m = z3;
            this.f = true;
        }
        return z2;
    }

    public final void d() {
        if (this.f) {
            this.k = 0L;
            this.j = DefinitionKt.NO_Float_VALUE;
            this.e = null;
            this.f = false;
            this.g = false;
            androidx.compose.ui.graphics.N n = this.c;
            Outline outline = this.b;
            if (n == null || !this.m || androidx.compose.ui.geometry.e.d(this.l) <= DefinitionKt.NO_Float_VALUE || androidx.compose.ui.geometry.e.b(this.l) <= DefinitionKt.NO_Float_VALUE) {
                outline.setEmpty();
                return;
            }
            this.a = true;
            if (n instanceof androidx.compose.ui.graphics.L) {
                androidx.compose.ui.geometry.c cVar = ((androidx.compose.ui.graphics.L) n).a;
                float f = cVar.a;
                float f2 = cVar.b;
                this.k = Q4.c(f, f2);
                this.l = T4.a(cVar.e(), cVar.d());
                outline.setRect(Math.round(f), Math.round(f2), Math.round(cVar.c), Math.round(cVar.d));
                return;
            }
            if (!(n instanceof androidx.compose.ui.graphics.M)) {
                if (n instanceof androidx.compose.ui.graphics.K) {
                    e(((androidx.compose.ui.graphics.K) n).a);
                    return;
                }
                return;
            }
            androidx.compose.ui.geometry.d dVar = ((androidx.compose.ui.graphics.M) n).a;
            float fB = androidx.compose.ui.geometry.a.b(dVar.e);
            float f3 = dVar.a;
            float f4 = dVar.b;
            this.k = Q4.c(f3, f4);
            this.l = T4.a(dVar.b(), dVar.a());
            if (S4.g(dVar)) {
                this.b.setRoundRect(Math.round(f3), Math.round(f4), Math.round(dVar.c), Math.round(dVar.d), fB);
                this.j = fB;
                return;
            }
            C0850j c0850jH = this.d;
            if (c0850jH == null) {
                c0850jH = androidx.compose.ui.graphics.F.h();
                this.d = c0850jH;
            }
            c0850jH.e();
            androidx.compose.ui.graphics.O.b(c0850jH, dVar);
            e(c0850jH);
        }
    }

    public final void e(androidx.compose.ui.graphics.O o) {
        int i = Build.VERSION.SDK_INT;
        Outline outline = this.b;
        if (i <= 28 && !((C0850j) o).a.isConvex()) {
            this.a = false;
            outline.setEmpty();
            this.g = true;
        } else {
            if (!(o instanceof C0850j)) {
                throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
            }
            outline.setConvexPath(((C0850j) o).a);
            this.g = !outline.canClip();
        }
        this.e = o;
    }
}
