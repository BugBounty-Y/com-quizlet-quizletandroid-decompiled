package androidx.compose.ui.platform;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.os.Build;
import android.view.DisplayListCanvas;
import android.view.RenderNode;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.C0859t;

/* loaded from: classes.dex */
public final class G0 implements InterfaceC0959o0 {
    public static boolean g = true;
    public final RenderNode a;
    public int b;
    public int c;
    public int d;
    public int e;
    public boolean f;

    public G0(C0971v c0971v) {
        RenderNode renderNodeCreate = RenderNode.create("Compose", c0971v);
        this.a = renderNodeCreate;
        if (g) {
            renderNodeCreate.setScaleX(renderNodeCreate.getScaleX());
            renderNodeCreate.setScaleY(renderNodeCreate.getScaleY());
            renderNodeCreate.setTranslationX(renderNodeCreate.getTranslationX());
            renderNodeCreate.setTranslationY(renderNodeCreate.getTranslationY());
            renderNodeCreate.setElevation(renderNodeCreate.getElevation());
            renderNodeCreate.setRotation(renderNodeCreate.getRotation());
            renderNodeCreate.setRotationX(renderNodeCreate.getRotationX());
            renderNodeCreate.setRotationY(renderNodeCreate.getRotationY());
            renderNodeCreate.setCameraDistance(renderNodeCreate.getCameraDistance());
            renderNodeCreate.setPivotX(renderNodeCreate.getPivotX());
            renderNodeCreate.setPivotY(renderNodeCreate.getPivotY());
            renderNodeCreate.setClipToOutline(renderNodeCreate.getClipToOutline());
            renderNodeCreate.setClipToBounds(false);
            renderNodeCreate.setAlpha(renderNodeCreate.getAlpha());
            renderNodeCreate.isValid();
            renderNodeCreate.setLeftTopRightBottom(0, 0, 0, 0);
            renderNodeCreate.offsetLeftAndRight(0);
            renderNodeCreate.offsetTopAndBottom(0);
            if (Build.VERSION.SDK_INT >= 28) {
                M0 m0 = M0.a;
                m0.c(renderNodeCreate, m0.a(renderNodeCreate));
                m0.d(renderNodeCreate, m0.b(renderNodeCreate));
            }
            L0.a.a(renderNodeCreate);
            renderNodeCreate.setLayerType(0);
            renderNodeCreate.setHasOverlappingRendering(renderNodeCreate.hasOverlappingRendering());
            g = false;
        }
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void A(Outline outline) {
        this.a.setOutline(outline);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean B() {
        return this.a.setHasOverlappingRendering(true);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean C() {
        return this.f;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int D() {
        return this.c;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void E(int i) {
        if (Build.VERSION.SDK_INT >= 28) {
            M0.a.c(this.a, i);
        }
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int F() {
        return this.d;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean G() {
        return this.a.getClipToOutline();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void H(boolean z) {
        this.a.setClipToOutline(z);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void I(int i) {
        if (Build.VERSION.SDK_INT >= 28) {
            M0.a.d(this.a, i);
        }
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void J(Matrix matrix) {
        this.a.getMatrix(matrix);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final float K() {
        return this.a.getElevation();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final float a() {
        return this.a.getAlpha();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int b() {
        return this.e - this.c;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void c(float f) {
        this.a.setRotationY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void d(float f) {
        this.a.setRotation(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void e(float f) {
        this.a.setTranslationY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void f() {
        L0.a.a(this.a);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void g(float f) {
        this.a.setScaleY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int getWidth() {
        return this.d - this.b;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean h() {
        return this.a.isValid();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void i(float f) {
        this.a.setAlpha(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void j(float f) {
        this.a.setScaleX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void k(float f) {
        this.a.setTranslationX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void l(float f) {
        this.a.setCameraDistance(-f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void m(C0856p c0856p) {
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void n(float f) {
        this.a.setRotationX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void o(int i) {
        this.b += i;
        this.d += i;
        this.a.offsetLeftAndRight(i);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int p() {
        return this.e;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void q(Canvas canvas) {
        ((DisplayListCanvas) canvas).drawRenderNode(this.a);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int r() {
        return this.b;
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void s(float f) {
        this.a.setPivotX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void t(boolean z) {
        this.f = z;
        this.a.setClipToBounds(z);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean u(int i, int i2, int i3, int i4) {
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        return this.a.setLeftTopRightBottom(i, i2, i3, i4);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void v(C0859t c0859t, androidx.compose.ui.graphics.O o, C0775b0 c0775b0) {
        Canvas canvasStart = this.a.start(getWidth(), b());
        C0844d c0844d = c0859t.a;
        Canvas canvas = c0844d.a;
        c0844d.a = canvasStart;
        if (o != null) {
            c0844d.e();
            c0844d.i(o);
        }
        c0775b0.invoke(c0844d);
        if (o != null) {
            c0844d.q();
        }
        c0859t.a.a = canvas;
        this.a.end(canvasStart);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void w(float f) {
        this.a.setPivotY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void x(float f) {
        this.a.setElevation(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void y(int i) {
        this.c += i;
        this.e += i;
        this.a.offsetTopAndBottom(i);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void z(int i) {
        if (i == 1) {
            this.a.setLayerType(2);
            this.a.setHasOverlappingRendering(true);
        } else if (i == 2) {
            this.a.setLayerType(0);
            this.a.setHasOverlappingRendering(false);
        } else {
            this.a.setLayerType(0);
            this.a.setHasOverlappingRendering(true);
        }
    }
}
