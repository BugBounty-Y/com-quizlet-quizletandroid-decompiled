package androidx.compose.ui.graphics.layer;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.RecordingCanvas;
import android.graphics.RenderNode;
import android.os.Build;
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
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public final class g implements d {
    public final C0859t b;
    public final androidx.compose.ui.graphics.drawscope.b c;
    public final RenderNode d;
    public long e;
    public Matrix f;
    public boolean g;
    public float h;
    public final int i;
    public float j;
    public float k;
    public float l;
    public float m;
    public float n;
    public long o;
    public long p;
    public float q;
    public float r;
    public float s;
    public float t;
    public boolean u;
    public boolean v;
    public boolean w;
    public C0856p x;
    public int y;

    public g() {
        C0859t c0859t = new C0859t();
        androidx.compose.ui.graphics.drawscope.b bVar = new androidx.compose.ui.graphics.drawscope.b();
        this.b = c0859t;
        this.c = bVar;
        RenderNode renderNodeD = f.d();
        this.d = renderNodeD;
        this.e = 0L;
        renderNodeD.setClipToBounds(false);
        N(renderNodeD, 0);
        this.h = 1.0f;
        this.i = 3;
        this.j = 1.0f;
        this.k = 1.0f;
        long j = C0861v.b;
        this.o = j;
        this.p = j;
        this.t = 8.0f;
        this.y = 0;
    }

    public static void N(RenderNode renderNode, int i) {
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

    @Override // androidx.compose.ui.graphics.layer.d
    public final long A() {
        return this.p;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void B(long j) {
        this.o = j;
        this.d.setAmbientShadowColor(F.A(j));
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float C() {
        return this.t;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float D() {
        return this.l;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void E(boolean z) {
        this.u = z;
        b();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float F() {
        return this.q;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void G(int i) {
        this.y = i;
        if (i != 1 && this.i == 3 && this.x == null) {
            N(this.d, i);
        } else {
            N(this.d, 1);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void H(long j) {
        this.p = j;
        this.d.setSpotShadowColor(F.A(j));
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final Matrix I() {
        Matrix matrix = this.f;
        if (matrix == null) {
            matrix = new Matrix();
            this.f = matrix;
        }
        this.d.getMatrix(matrix);
        return matrix;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float J() {
        return this.n;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float K() {
        return this.k;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int L() {
        return this.i;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void M(InterfaceC0858s interfaceC0858s) {
        AbstractC0845e.a(interfaceC0858s).drawRenderNode(this.d);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float a() {
        return this.h;
    }

    public final void b() {
        boolean z = this.u;
        boolean z2 = false;
        boolean z3 = z && !this.g;
        if (z && this.g) {
            z2 = true;
        }
        if (z3 != this.v) {
            this.v = z3;
            this.d.setClipToBounds(z3);
        }
        if (z2 != this.w) {
            this.w = z2;
            this.d.setClipToOutline(z2);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void c(float f) {
        this.r = f;
        this.d.setRotationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void d(float f) {
        this.s = f;
        this.d.setRotationZ(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void e(float f) {
        this.m = f;
        this.d.setTranslationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void f() {
        this.d.discardDisplayList();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void g(float f) {
        this.k = f;
        this.d.setScaleY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final boolean h() {
        return this.d.hasDisplayList();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void i(float f) {
        this.h = f;
        this.d.setAlpha(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void j(float f) {
        this.j = f;
        this.d.setScaleX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void k(float f) {
        this.l = f;
        this.d.setTranslationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void l(float f) {
        this.t = f;
        this.d.setCameraDistance(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void m(C0856p c0856p) {
        this.x = c0856p;
        if (Build.VERSION.SDK_INT >= 31) {
            n.a.a(this.d, c0856p);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void n(float f) {
        this.q = f;
        this.d.setRotationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float o() {
        return this.j;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void p(float f) {
        this.n = f;
        this.d.setElevation(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final P q() {
        return this.x;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void r(Outline outline, long j) {
        this.d.setOutline(outline);
        this.g = outline != null;
        b();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int s() {
        return this.y;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void t(int i, int i2, long j) {
        this.d.setPosition(i, i2, ((int) (j >> 32)) + i, ((int) (4294967295L & j)) + i2);
        this.e = R5.f(j);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float u() {
        return this.r;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float v() {
        return this.s;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void w(long j) {
        if (Q4.i(j)) {
            this.d.resetPivot();
        } else {
            this.d.setPivotX(androidx.compose.ui.geometry.b.d(j));
            this.d.setPivotY(androidx.compose.ui.geometry.b.e(j));
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final long x() {
        return this.o;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void y(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar, b bVar2, C0775b0 c0775b0) {
        androidx.compose.ui.graphics.drawscope.b bVar3 = this.c;
        RecordingCanvas recordingCanvasBeginRecording = this.d.beginRecording();
        try {
            C0859t c0859t = this.b;
            C0844d c0844d = c0859t.a;
            Canvas canvas = c0844d.a;
            c0844d.a = recordingCanvasBeginRecording;
            com.quizlet.data.repository.folderset.c cVar = bVar3.b;
            cVar.w(bVar);
            cVar.x(kVar);
            cVar.c = bVar2;
            cVar.y(this.e);
            cVar.v(c0844d);
            c0775b0.invoke(bVar3);
            c0859t.a.a = canvas;
        } finally {
            this.d.endRecording();
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float z() {
        return this.m;
    }
}
