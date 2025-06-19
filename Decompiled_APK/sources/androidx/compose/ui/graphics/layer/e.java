package androidx.compose.ui.graphics.layer;

import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.Paint;
import android.os.Build;
import android.view.DisplayListCanvas;
import android.view.RenderNode;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0856p;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.graphics.P;
import androidx.compose.ui.platform.C0971v;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements d {
    public static final AtomicBoolean B = new AtomicBoolean(true);
    public C0856p A;
    public final C0859t b;
    public final androidx.compose.ui.graphics.drawscope.b c;
    public final RenderNode d;
    public long e;
    public Matrix f;
    public boolean g;
    public long h;
    public int i;
    public final int j;
    public float k;
    public boolean l;
    public float m;
    public float n;
    public float o;
    public float p;
    public float q;
    public long r;
    public long s;
    public float t;
    public float u;
    public float v;
    public float w;
    public boolean x;
    public boolean y;
    public boolean z;

    public e(C0971v c0971v, C0859t c0859t, androidx.compose.ui.graphics.drawscope.b bVar) {
        this.b = c0859t;
        this.c = bVar;
        RenderNode renderNodeCreate = RenderNode.create("Compose", c0971v);
        this.d = renderNodeCreate;
        this.e = 0L;
        this.h = 0L;
        if (B.getAndSet(false)) {
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
                m mVar = m.a;
                mVar.c(renderNodeCreate, mVar.a(renderNodeCreate));
                mVar.d(renderNodeCreate, mVar.b(renderNodeCreate));
            }
            l.a.a(renderNodeCreate);
            renderNodeCreate.setLayerType(0);
            renderNodeCreate.setHasOverlappingRendering(renderNodeCreate.hasOverlappingRendering());
        }
        renderNodeCreate.setClipToBounds(false);
        N(0);
        this.i = 0;
        this.j = 3;
        this.k = 1.0f;
        this.m = 1.0f;
        this.n = 1.0f;
        long j = C0861v.b;
        this.r = j;
        this.s = j;
        this.w = 8.0f;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final long A() {
        return this.s;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void B(long j) {
        if (Build.VERSION.SDK_INT >= 28) {
            this.r = j;
            m.a.c(this.d, F.A(j));
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float C() {
        return this.w;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float D() {
        return this.o;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void E(boolean z) {
        this.x = z;
        b();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float F() {
        return this.t;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void G(int i) {
        this.i = i;
        if (i != 1 && this.j == 3) {
            N(i);
        } else {
            N(1);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void H(long j) {
        if (Build.VERSION.SDK_INT >= 28) {
            this.s = j;
            m.a.d(this.d, F.A(j));
        }
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
        return this.q;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float K() {
        return this.n;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int L() {
        return this.j;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void M(InterfaceC0858s interfaceC0858s) {
        DisplayListCanvas displayListCanvasA = AbstractC0845e.a(interfaceC0858s);
        Intrinsics.e(displayListCanvasA, "null cannot be cast to non-null type android.view.DisplayListCanvas");
        displayListCanvasA.drawRenderNode(this.d);
    }

    public final void N(int i) {
        RenderNode renderNode = this.d;
        if (i == 1) {
            renderNode.setLayerType(2);
            renderNode.setLayerPaint((Paint) null);
            renderNode.setHasOverlappingRendering(true);
        } else if (i == 2) {
            renderNode.setLayerType(0);
            renderNode.setLayerPaint((Paint) null);
            renderNode.setHasOverlappingRendering(false);
        } else {
            renderNode.setLayerType(0);
            renderNode.setLayerPaint((Paint) null);
            renderNode.setHasOverlappingRendering(true);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float a() {
        return this.k;
    }

    public final void b() {
        boolean z = this.x;
        boolean z2 = false;
        boolean z3 = z && !this.g;
        if (z && this.g) {
            z2 = true;
        }
        if (z3 != this.y) {
            this.y = z3;
            this.d.setClipToBounds(z3);
        }
        if (z2 != this.z) {
            this.z = z2;
            this.d.setClipToOutline(z2);
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void c(float f) {
        this.u = f;
        this.d.setRotationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void d(float f) {
        this.v = f;
        this.d.setRotation(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void e(float f) {
        this.p = f;
        this.d.setTranslationY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void f() {
        l.a.a(this.d);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void g(float f) {
        this.n = f;
        this.d.setScaleY(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final boolean h() {
        return this.d.isValid();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void i(float f) {
        this.k = f;
        this.d.setAlpha(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void j(float f) {
        this.m = f;
        this.d.setScaleX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void k(float f) {
        this.o = f;
        this.d.setTranslationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void l(float f) {
        this.w = f;
        this.d.setCameraDistance(-f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void m(C0856p c0856p) {
        this.A = c0856p;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void n(float f) {
        this.t = f;
        this.d.setRotationX(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float o() {
        return this.m;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void p(float f) {
        this.q = f;
        this.d.setElevation(f);
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final P q() {
        return this.A;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void r(Outline outline, long j) {
        this.h = j;
        this.d.setOutline(outline);
        this.g = outline != null;
        b();
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final int s() {
        return this.i;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void t(int i, int i2, long j) {
        int i3 = (int) (j >> 32);
        int i4 = (int) (4294967295L & j);
        this.d.setLeftTopRightBottom(i, i2, i + i3, i2 + i4);
        if (androidx.compose.ui.unit.j.a(this.e, j)) {
            return;
        }
        if (this.l) {
            this.d.setPivotX(i3 / 2.0f);
            this.d.setPivotY(i4 / 2.0f);
        }
        this.e = j;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float u() {
        return this.u;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float v() {
        return this.v;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void w(long j) {
        if (Q4.i(j)) {
            this.l = true;
            this.d.setPivotX(((int) (this.e >> 32)) / 2.0f);
            this.d.setPivotY(((int) (this.e & 4294967295L)) / 2.0f);
        } else {
            this.l = false;
            this.d.setPivotX(androidx.compose.ui.geometry.b.d(j));
            this.d.setPivotY(androidx.compose.ui.geometry.b.e(j));
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final long x() {
        return this.r;
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final void y(androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar, b bVar2, C0775b0 c0775b0) {
        Canvas canvasStart = this.d.start(Math.max((int) (this.e >> 32), (int) (this.h >> 32)), Math.max((int) (this.e & 4294967295L), (int) (this.h & 4294967295L)));
        try {
            C0844d c0844d = this.b.a;
            Canvas canvas = c0844d.a;
            c0844d.a = canvasStart;
            androidx.compose.ui.graphics.drawscope.b bVar3 = this.c;
            com.quizlet.data.repository.folderset.c cVar = bVar3.b;
            long jF = R5.f(this.e);
            androidx.compose.ui.graphics.drawscope.a aVar = ((androidx.compose.ui.graphics.drawscope.b) cVar.d).a;
            androidx.compose.ui.unit.b bVar4 = aVar.a;
            androidx.compose.ui.unit.k kVar2 = aVar.b;
            InterfaceC0858s interfaceC0858sO = cVar.o();
            long jR = cVar.r();
            b bVar5 = (b) cVar.c;
            cVar.w(bVar);
            cVar.x(kVar);
            cVar.v(c0844d);
            cVar.y(jF);
            cVar.c = bVar2;
            c0844d.e();
            try {
                c0775b0.invoke(bVar3);
                c0844d.q();
                cVar.w(bVar4);
                cVar.x(kVar2);
                cVar.v(interfaceC0858sO);
                cVar.y(jR);
                cVar.c = bVar5;
                c0844d.a = canvas;
                this.d.end(canvasStart);
            } catch (Throwable th) {
                c0844d.q();
                cVar.w(bVar4);
                cVar.x(kVar2);
                cVar.v(interfaceC0858sO);
                cVar.y(jR);
                cVar.c = bVar5;
                throw th;
            }
        } catch (Throwable th2) {
            this.d.end(canvasStart);
            throw th2;
        }
    }

    @Override // androidx.compose.ui.graphics.layer.d
    public final float z() {
        return this.p;
    }
}
