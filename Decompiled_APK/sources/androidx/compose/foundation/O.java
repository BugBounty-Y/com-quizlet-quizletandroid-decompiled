package androidx.compose.foundation;

import android.graphics.Canvas;
import android.graphics.RecordingCanvas;
import android.graphics.RenderNode;
import android.os.Build;
import android.widget.EdgeEffect;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class O extends androidx.compose.ui.platform.N implements androidx.compose.ui.draw.f {
    public final /* synthetic */ int d = 1;
    public final C0456n e;
    public final P f;
    public Object g;

    public O(C0456n c0456n, P p) {
        this.e = c0456n;
        this.f = p;
    }

    public static boolean J(float f, EdgeEffect edgeEffect, Canvas canvas) {
        if (f == DefinitionKt.NO_Float_VALUE) {
            return edgeEffect.draw(canvas);
        }
        int iSave = canvas.save();
        canvas.rotate(f);
        boolean zDraw = edgeEffect.draw(canvas);
        canvas.restoreToCount(iSave);
        return zDraw;
    }

    public static boolean K(float f, long j, EdgeEffect edgeEffect, Canvas canvas) {
        int iSave = canvas.save();
        canvas.rotate(f);
        canvas.translate(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        boolean zDraw = edgeEffect.draw(canvas);
        canvas.restoreToCount(iSave);
        return zDraw;
    }

    public RenderNode L() {
        RenderNode renderNode = (RenderNode) this.g;
        if (renderNode != null) {
            return renderNode;
        }
        RenderNode renderNodeD = androidx.activity.z.d();
        this.g = renderNodeD;
        return renderNodeD;
    }

    @Override // androidx.compose.ui.draw.f
    public final void e(androidx.compose.ui.node.G g) {
        float f;
        boolean zJ;
        float f2;
        float f3;
        float f4;
        switch (this.d) {
            case 0:
                androidx.compose.ui.graphics.drawscope.b bVar = g.a;
                long jG = bVar.g();
                C0456n c0456n = this.e;
                c0456n.l(jG);
                if (androidx.compose.ui.geometry.e.e(bVar.g())) {
                    g.b();
                    return;
                }
                g.b();
                ((androidx.compose.runtime.L0) c0456n.c).getValue();
                Canvas canvasA = AbstractC0845e.a(bVar.b.o());
                P p = this.f;
                boolean zF = P.f(p.f);
                androidx.compose.foundation.layout.A0 a0 = ((A0) this.g).b;
                boolean zK = zF ? K(270.0f, Q4.c(-androidx.compose.ui.geometry.e.b(bVar.g()), g.c0(a0.b(g.getLayoutDirection()))), p.c(), canvasA) : false;
                if (P.f(p.d)) {
                    zK = K(DefinitionKt.NO_Float_VALUE, Q4.c(DefinitionKt.NO_Float_VALUE, g.c0(a0.b)), p.e(), canvasA) || zK;
                }
                if (P.f(p.g)) {
                    zK = K(90.0f, Q4.c(DefinitionKt.NO_Float_VALUE, g.c0(a0.c(g.getLayoutDirection())) + (-((float) kotlin.math.c.b(androidx.compose.ui.geometry.e.d(bVar.g()))))), p.d(), canvasA) || zK;
                }
                if (P.f(p.e)) {
                    zK = K(180.0f, Q4.c(-androidx.compose.ui.geometry.e.d(bVar.g()), (-androidx.compose.ui.geometry.e.b(bVar.g())) + g.c0(a0.d)), p.b(), canvasA) || zK;
                }
                if (zK) {
                    c0456n.g();
                    return;
                }
                return;
            default:
                androidx.compose.ui.graphics.drawscope.b bVar2 = g.a;
                long jG2 = bVar2.g();
                C0456n c0456n2 = this.e;
                c0456n2.l(jG2);
                if (androidx.compose.ui.geometry.e.e(bVar2.g())) {
                    g.b();
                    return;
                }
                ((androidx.compose.runtime.L0) c0456n2.c).getValue();
                float fC0 = g.c0(G.a);
                Canvas canvasA2 = AbstractC0845e.a(bVar2.b.o());
                P p2 = this.f;
                boolean z = P.f(p2.d) || P.g(p2.h) || P.f(p2.e) || P.g(p2.i);
                boolean z2 = P.f(p2.f) || P.g(p2.j) || P.f(p2.g) || P.g(p2.k);
                if (z && z2) {
                    L().setPosition(0, 0, canvasA2.getWidth(), canvasA2.getHeight());
                } else if (z) {
                    L().setPosition(0, 0, (kotlin.math.c.b(fC0) * 2) + canvasA2.getWidth(), canvasA2.getHeight());
                } else {
                    if (!z2) {
                        g.b();
                        return;
                    }
                    L().setPosition(0, 0, canvasA2.getWidth(), (kotlin.math.c.b(fC0) * 2) + canvasA2.getHeight());
                }
                RecordingCanvas recordingCanvasBeginRecording = L().beginRecording();
                if (P.g(p2.j)) {
                    EdgeEffect edgeEffectA = p2.j;
                    if (edgeEffectA == null) {
                        edgeEffectA = p2.a();
                        p2.j = edgeEffectA;
                    }
                    J(90.0f, edgeEffectA, recordingCanvasBeginRecording);
                    edgeEffectA.finish();
                }
                boolean zF2 = P.f(p2.f);
                C0458o c0458o = C0458o.a;
                if (zF2) {
                    EdgeEffect edgeEffectC = p2.c();
                    zJ = J(270.0f, edgeEffectC, recordingCanvasBeginRecording);
                    if (P.g(p2.f)) {
                        float fE = androidx.compose.ui.geometry.b.e(c0456n2.e());
                        EdgeEffect edgeEffectA2 = p2.j;
                        if (edgeEffectA2 == null) {
                            edgeEffectA2 = p2.a();
                            p2.j = edgeEffectA2;
                        }
                        int i = Build.VERSION.SDK_INT;
                        float fB = i >= 31 ? c0458o.b(edgeEffectC) : DefinitionKt.NO_Float_VALUE;
                        f = fC0;
                        float f5 = 1 - fE;
                        if (i >= 31) {
                            c0458o.c(edgeEffectA2, fB, f5);
                        } else {
                            edgeEffectA2.onPull(fB, f5);
                        }
                    } else {
                        f = fC0;
                    }
                } else {
                    f = fC0;
                    zJ = false;
                }
                if (P.g(p2.h)) {
                    EdgeEffect edgeEffectA3 = p2.h;
                    if (edgeEffectA3 == null) {
                        edgeEffectA3 = p2.a();
                        p2.h = edgeEffectA3;
                    }
                    J(180.0f, edgeEffectA3, recordingCanvasBeginRecording);
                    edgeEffectA3.finish();
                }
                if (P.f(p2.d)) {
                    EdgeEffect edgeEffectE = p2.e();
                    boolean z3 = J(DefinitionKt.NO_Float_VALUE, edgeEffectE, recordingCanvasBeginRecording) || zJ;
                    if (P.g(p2.d)) {
                        float fD = androidx.compose.ui.geometry.b.d(c0456n2.e());
                        EdgeEffect edgeEffectA4 = p2.h;
                        if (edgeEffectA4 == null) {
                            edgeEffectA4 = p2.a();
                            p2.h = edgeEffectA4;
                        }
                        int i2 = Build.VERSION.SDK_INT;
                        float fB2 = i2 >= 31 ? c0458o.b(edgeEffectE) : DefinitionKt.NO_Float_VALUE;
                        if (i2 >= 31) {
                            c0458o.c(edgeEffectA4, fB2, fD);
                        } else {
                            edgeEffectA4.onPull(fB2, fD);
                        }
                    }
                    zJ = z3;
                }
                if (P.g(p2.k)) {
                    EdgeEffect edgeEffectA5 = p2.k;
                    if (edgeEffectA5 == null) {
                        edgeEffectA5 = p2.a();
                        p2.k = edgeEffectA5;
                    }
                    J(270.0f, edgeEffectA5, recordingCanvasBeginRecording);
                    edgeEffectA5.finish();
                }
                if (P.f(p2.g)) {
                    EdgeEffect edgeEffectD = p2.d();
                    boolean z4 = J(90.0f, edgeEffectD, recordingCanvasBeginRecording) || zJ;
                    if (P.g(p2.g)) {
                        float fE2 = androidx.compose.ui.geometry.b.e(c0456n2.e());
                        EdgeEffect edgeEffectA6 = p2.k;
                        if (edgeEffectA6 == null) {
                            edgeEffectA6 = p2.a();
                            p2.k = edgeEffectA6;
                        }
                        int i3 = Build.VERSION.SDK_INT;
                        float fB3 = i3 >= 31 ? c0458o.b(edgeEffectD) : DefinitionKt.NO_Float_VALUE;
                        if (i3 >= 31) {
                            c0458o.c(edgeEffectA6, fB3, fE2);
                        } else {
                            edgeEffectA6.onPull(fB3, fE2);
                        }
                    }
                    zJ = z4;
                }
                if (P.g(p2.i)) {
                    EdgeEffect edgeEffectA7 = p2.i;
                    if (edgeEffectA7 == null) {
                        edgeEffectA7 = p2.a();
                        p2.i = edgeEffectA7;
                    }
                    f2 = DefinitionKt.NO_Float_VALUE;
                    J(DefinitionKt.NO_Float_VALUE, edgeEffectA7, recordingCanvasBeginRecording);
                    edgeEffectA7.finish();
                } else {
                    f2 = DefinitionKt.NO_Float_VALUE;
                }
                if (P.f(p2.e)) {
                    EdgeEffect edgeEffectB = p2.b();
                    boolean z5 = J(180.0f, edgeEffectB, recordingCanvasBeginRecording) || zJ;
                    if (P.g(p2.e)) {
                        float fD2 = androidx.compose.ui.geometry.b.d(c0456n2.e());
                        EdgeEffect edgeEffectA8 = p2.i;
                        if (edgeEffectA8 == null) {
                            edgeEffectA8 = p2.a();
                            p2.i = edgeEffectA8;
                        }
                        int i4 = Build.VERSION.SDK_INT;
                        float fB4 = i4 >= 31 ? c0458o.b(edgeEffectB) : f2;
                        float f6 = 1 - fD2;
                        if (i4 >= 31) {
                            c0458o.c(edgeEffectA8, fB4, f6);
                        } else {
                            edgeEffectA8.onPull(fB4, f6);
                        }
                    }
                    zJ = z5;
                }
                if (zJ) {
                    c0456n2.g();
                }
                float f7 = z2 ? f2 : f;
                if (!z) {
                    f2 = f;
                }
                androidx.compose.ui.unit.k layoutDirection = g.getLayoutDirection();
                C0844d c0844d = new C0844d();
                c0844d.a = recordingCanvasBeginRecording;
                long jG3 = bVar2.g();
                com.quizlet.data.repository.folderset.c cVar = bVar2.b;
                androidx.compose.ui.graphics.drawscope.a aVar = ((androidx.compose.ui.graphics.drawscope.b) cVar.d).a;
                androidx.compose.ui.unit.b bVar3 = aVar.a;
                androidx.compose.ui.unit.k kVar = aVar.b;
                InterfaceC0858s interfaceC0858sO = cVar.o();
                long jR = bVar2.b.r();
                com.quizlet.data.repository.folderset.c cVar2 = bVar2.b;
                androidx.compose.ui.graphics.layer.b bVar4 = (androidx.compose.ui.graphics.layer.b) cVar2.c;
                cVar2.w(g);
                cVar2.x(layoutDirection);
                cVar2.v(c0844d);
                cVar2.y(jG3);
                cVar2.c = null;
                c0844d.e();
                try {
                    ((androidx.appcompat.app.L) bVar2.b.b).S(f7, f2);
                    try {
                        g.b();
                        c0844d.q();
                        com.quizlet.data.repository.folderset.c cVar3 = bVar2.b;
                        cVar3.w(bVar3);
                        cVar3.x(kVar);
                        cVar3.v(interfaceC0858sO);
                        cVar3.y(jR);
                        cVar3.c = bVar4;
                        L().endRecording();
                        int iSave = canvasA2.save();
                        canvasA2.translate(f3, f4);
                        canvasA2.drawRenderNode(L());
                        canvasA2.restoreToCount(iSave);
                        return;
                    } finally {
                        ((androidx.appcompat.app.L) bVar2.b.b).S(-f7, -f2);
                    }
                } catch (Throwable th) {
                    c0844d.q();
                    com.quizlet.data.repository.folderset.c cVar4 = bVar2.b;
                    cVar4.w(bVar3);
                    cVar4.x(kVar);
                    cVar4.v(interfaceC0858sO);
                    cVar4.y(jR);
                    cVar4.c = bVar4;
                    throw th;
                }
        }
    }

    public O(C0456n c0456n, P p, A0 a0) {
        this.e = c0456n;
        this.f = p;
        this.g = a0;
    }
}
