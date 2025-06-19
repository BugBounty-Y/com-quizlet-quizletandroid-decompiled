package androidx.compose.ui.graphics.layer;

import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import android.view.ViewParent;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.P;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public final class i implements d {
    public static final h B = new h();
    public C0856p A;
    public final androidx.compose.ui.graphics.layer.view.a b;
    public final C0859t c;
    public final o d;
    public final Resources e;
    public final Rect f;
    public int g;
    public int h;
    public long i;
    public boolean j;
    public boolean k;
    public boolean l;
    public final int m;
    public int n;
    public float o;
    public boolean p;
    public float q;
    public float r;
    public float s;
    public float t;
    public float u;
    public long v;
    public long w;
    public float x;
    public float y;
    public float z;

    public i(androidx.compose.ui.graphics.layer.view.a aVar) {
        C0859t c0859t = new C0859t();
        androidx.compose.ui.graphics.drawscope.b bVar = new androidx.compose.ui.graphics.drawscope.b();
        this.b = aVar;
        this.c = c0859t;
        o oVar = new o(aVar, c0859t, bVar);
        this.d = oVar;
        this.e = aVar.getResources();
        this.f = new Rect();
        aVar.addView(oVar);
        oVar.setClipBounds(null);
        this.i = 0L;
        View.generateViewId();
        this.m = 3;
        this.n = 0;
        this.o = 1.0f;
        this.q = 1.0f;
        this.r = 1.0f;
        long j = C0861v.b;
        this.v = j;
        this.w = j;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final long A() {
        return this.w;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void B(long j) {
        if (Build.VERSION.SDK_INT >= 28) {
            this.v = j;
            this.d.setOutlineAmbientShadowColor(F.A(j));
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float C() {
        return this.d.getCameraDistance() / this.e.getDisplayMetrics().densityDpi;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float D() {
        return this.s;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void E(boolean z) {
        boolean z2 = false;
        this.l = z && !this.k;
        this.j = true;
        if (z && this.k) {
            z2 = true;
        }
        this.d.setClipToOutline(z2);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float F() {
        return this.x;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void G(int i) {
        this.n = i;
        o oVar = this.d;
        boolean z = true;
        if (i == 1 || this.m != 3) {
            oVar.setLayerType(2, null);
            oVar.setCanUseCompositingLayer$ui_graphics_release(true);
            return;
        }
        if (i == 1) {
            oVar.setLayerType(2, null);
        } else if (i == 2) {
            oVar.setLayerType(0, null);
            z = false;
        } else {
            oVar.setLayerType(0, null);
        }
        oVar.setCanUseCompositingLayer$ui_graphics_release(z);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void H(long j) {
        if (Build.VERSION.SDK_INT >= 28) {
            this.w = j;
            this.d.setOutlineSpotShadowColor(F.A(j));
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final Matrix I() {
        return this.d.getMatrix();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float J() {
        return this.u;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float K() {
        return this.r;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int L() {
        return this.m;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void M(InterfaceC0858s interfaceC0858s) {
        Rect rect;
        boolean z = this.j;
        o oVar = this.d;
        if (z) {
            if ((this.l || oVar.getClipToOutline()) && !this.k) {
                rect = this.f;
                rect.left = 0;
                rect.top = 0;
                rect.right = oVar.getWidth();
                rect.bottom = oVar.getHeight();
            } else {
                rect = null;
            }
            oVar.setClipBounds(rect);
        }
        if (AbstractC0845e.a(interfaceC0858s).isHardwareAccelerated()) {
            this.b.a(interfaceC0858s, oVar, oVar.getDrawingTime());
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float a() {
        return this.o;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void c(float f) {
        this.y = f;
        this.d.setRotationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void d(float f) {
        this.z = f;
        this.d.setRotation(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void e(float f) {
        this.t = f;
        this.d.setTranslationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void f() {
        this.b.removeViewInLayout(this.d);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void g(float f) {
        this.r = f;
        this.d.setScaleY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void i(float f) {
        this.o = f;
        this.d.setAlpha(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void j(float f) {
        this.q = f;
        this.d.setScaleX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void k(float f) {
        this.s = f;
        this.d.setTranslationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void l(float f) {
        this.d.setCameraDistance(f * this.e.getDisplayMetrics().densityDpi);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void m(C0856p c0856p) {
        this.A = c0856p;
        if (Build.VERSION.SDK_INT >= 31) {
            this.d.setRenderEffect(c0856p != null ? c0856p.a() : null);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void n(float f) {
        this.x = f;
        this.d.setRotationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float o() {
        return this.q;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void p(float f) {
        this.u = f;
        this.d.setElevation(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final P q() {
        return this.A;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void r(Outline outline, long j) {
        o oVar = this.d;
        oVar.e = outline;
        oVar.invalidateOutline();
        if ((this.l || oVar.getClipToOutline()) && outline != null) {
            oVar.setClipToOutline(true);
            if (this.l) {
                this.l = false;
                this.j = true;
            }
        }
        this.k = outline != null;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int s() {
        return this.n;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void t(int i, int i2, long j) {
        boolean zA = androidx.compose.ui.unit.j.a(this.i, j);
        o oVar = this.d;
        if (zA) {
            int i3 = this.g;
            if (i3 != i) {
                oVar.offsetLeftAndRight(i - i3);
            }
            int i4 = this.h;
            if (i4 != i2) {
                oVar.offsetTopAndBottom(i2 - i4);
            }
        } else {
            if (this.l || oVar.getClipToOutline()) {
                this.j = true;
            }
            int i5 = (int) (j >> 32);
            int i6 = (int) (4294967295L & j);
            oVar.layout(i, i2, i + i5, i2 + i6);
            this.i = j;
            if (this.p) {
                oVar.setPivotX(i5 / 2.0f);
                oVar.setPivotY(i6 / 2.0f);
            }
        }
        this.g = i;
        this.h = i2;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float u() {
        return this.y;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float v() {
        return this.z;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void w(long j) {
        boolean zI = Q4.i(j);
        o oVar = this.d;
        if (!zI) {
            this.p = false;
            oVar.setPivotX(androidx.compose.ui.geometry.b.d(j));
            oVar.setPivotY(androidx.compose.ui.geometry.b.e(j));
        } else {
            if (Build.VERSION.SDK_INT >= 28) {
                oVar.resetPivot();
                return;
            }
            this.p = true;
            oVar.setPivotX(((int) (this.i >> 32)) / 2.0f);
            oVar.setPivotY(((int) (this.i & 4294967295L)) / 2.0f);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final long x() {
        return this.v;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void y(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar, b bVar2, C0775b0 c0775b0) {
        o oVar = this.d;
        ViewParent parent = oVar.getParent();
        androidx.compose.ui.graphics.layer.view.a aVar = this.b;
        if (parent == null) {
            aVar.addView(oVar);
        }
        oVar.g = bVar;
        oVar.h = kVar;
        oVar.i = c0775b0;
        oVar.j = bVar2;
        if (oVar.isAttachedToWindow()) {
            oVar.setVisibility(4);
            oVar.setVisibility(0);
            try {
                C0859t c0859t = this.c;
                h hVar = B;
                C0844d c0844d = c0859t.a;
                Canvas canvas = c0844d.a;
                c0844d.a = hVar;
                aVar.a(c0844d, oVar, oVar.getDrawingTime());
                c0859t.a.a = canvas;
            } catch (Throwable unused) {
            }
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float z() {
        return this.t;
    }
}
