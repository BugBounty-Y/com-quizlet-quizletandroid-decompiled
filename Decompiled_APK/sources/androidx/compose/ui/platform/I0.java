package androidx.compose.ui.platform;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.RecordingCanvas;
import android.graphics.RenderNode;
import android.os.Build;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.C0859t;

/* loaded from: classes.dex */
public final class I0 implements InterfaceC0959o0 {
    public final RenderNode a = androidx.compose.ui.graphics.layer.f.o();

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
        return this.a.getClipToBounds();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int D() {
        return this.a.getTop();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void E(int i) {
        this.a.setAmbientShadowColor(i);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int F() {
        return this.a.getRight();
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
        this.a.setSpotShadowColor(i);
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
        return this.a.getHeight();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void c(float f) {
        this.a.setRotationY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void d(float f) {
        this.a.setRotationZ(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void e(float f) {
        this.a.setTranslationY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void f() {
        this.a.discardDisplayList();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void g(float f) {
        this.a.setScaleY(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int getWidth() {
        return this.a.getWidth();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean h() {
        return this.a.hasDisplayList();
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
        this.a.setCameraDistance(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void m(C0856p c0856p) {
        if (Build.VERSION.SDK_INT >= 31) {
            J0.a.a(this.a, c0856p);
        }
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void n(float f) {
        this.a.setRotationX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void o(int i) {
        this.a.offsetLeftAndRight(i);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int p() {
        return this.a.getBottom();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void q(Canvas canvas) {
        canvas.drawRenderNode(this.a);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final int r() {
        return this.a.getLeft();
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void s(float f) {
        this.a.setPivotX(f);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void t(boolean z) {
        this.a.setClipToBounds(z);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final boolean u(int i, int i2, int i3, int i4) {
        return this.a.setPosition(i, i2, i3, i4);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void v(C0859t c0859t, androidx.compose.ui.graphics.O o, C0775b0 c0775b0) {
        RecordingCanvas recordingCanvasBeginRecording = this.a.beginRecording();
        C0844d c0844d = c0859t.a;
        Canvas canvas = c0844d.a;
        c0844d.a = recordingCanvasBeginRecording;
        if (o != null) {
            c0844d.e();
            c0844d.i(o);
        }
        c0775b0.invoke(c0844d);
        if (o != null) {
            c0844d.q();
        }
        c0859t.a.a = canvas;
        this.a.endRecording();
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
        this.a.offsetTopAndBottom(i);
    }

    @Override // androidx.compose.ui.platform.InterfaceC0959o0
    public final void z(int i) {
        RenderNode renderNode = this.a;
        if (i == 1) {
            renderNode.setUseCompositingLayer(true, null);
            renderNode.setHasOverlappingRendering(true);
        } else if (i == 2) {
            renderNode.setUseCompositingLayer(false, null);
            renderNode.setHasOverlappingRendering(false);
        } else {
            renderNode.setUseCompositingLayer(false, null);
            renderNode.setHasOverlappingRendering(true);
        }
    }
}
