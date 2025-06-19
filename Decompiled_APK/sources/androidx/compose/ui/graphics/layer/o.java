package androidx.compose.ui.graphics.layer;

import android.graphics.Canvas;
import android.graphics.Outline;
import android.view.View;
import androidx.compose.material3.C0634i2;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;
import kotlin.jvm.internal.r;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class o extends View {
    public static final C0634i2 k = new C0634i2(1);
    public final androidx.compose.ui.graphics.layer.view.a a;
    public final C0859t b;
    public final androidx.compose.ui.graphics.drawscope.b c;
    public boolean d;
    public Outline e;
    public boolean f;
    public androidx.compose.ui.unit.b g;
    public androidx.compose.ui.unit.k h;
    public r i;
    public b j;

    public o(androidx.compose.ui.graphics.layer.view.a aVar, C0859t c0859t, androidx.compose.ui.graphics.drawscope.b bVar) {
        super(aVar.getContext());
        this.a = aVar;
        this.b = c0859t;
        this.c = bVar;
        setOutlineProvider(k);
        this.f = true;
        this.g = androidx.compose.ui.graphics.drawscope.c.a;
        this.h = androidx.compose.ui.unit.k.a;
        d.a.getClass();
        this.i = a.c;
        setWillNotDraw(false);
        setClipBounds(null);
    }

    /* JADX WARN: Type inference failed for: r9v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // android.view.View
    public final void dispatchDraw(Canvas canvas) {
        C0859t c0859t = this.b;
        C0844d c0844d = c0859t.a;
        Canvas canvas2 = c0844d.a;
        c0844d.a = canvas;
        androidx.compose.ui.unit.b bVar = this.g;
        androidx.compose.ui.unit.k kVar = this.h;
        long jA = T4.a(getWidth(), getHeight());
        b bVar2 = this.j;
        ?? r9 = this.i;
        androidx.compose.ui.graphics.drawscope.b bVar3 = this.c;
        com.quizlet.data.repository.folderset.c cVar = bVar3.b;
        androidx.compose.ui.graphics.drawscope.a aVar = ((androidx.compose.ui.graphics.drawscope.b) cVar.d).a;
        androidx.compose.ui.unit.b bVar4 = aVar.a;
        androidx.compose.ui.unit.k kVar2 = aVar.b;
        InterfaceC0858s interfaceC0858sO = cVar.o();
        com.quizlet.data.repository.folderset.c cVar2 = bVar3.b;
        long jR = cVar2.r();
        b bVar5 = (b) cVar2.c;
        cVar2.w(bVar);
        cVar2.x(kVar);
        cVar2.v(c0844d);
        cVar2.y(jA);
        cVar2.c = bVar2;
        c0844d.e();
        try {
            r9.invoke(bVar3);
            c0844d.q();
            cVar2.w(bVar4);
            cVar2.x(kVar2);
            cVar2.v(interfaceC0858sO);
            cVar2.y(jR);
            cVar2.c = bVar5;
            c0859t.a.a = canvas2;
            this.d = false;
        } catch (Throwable th) {
            c0844d.q();
            cVar2.w(bVar4);
            cVar2.x(kVar2);
            cVar2.v(interfaceC0858sO);
            cVar2.y(jR);
            cVar2.c = bVar5;
            throw th;
        }
    }

    @Override // android.view.View
    public final void forceLayout() {
    }

    public final boolean getCanUseCompositingLayer$ui_graphics_release() {
        return this.f;
    }

    @NotNull
    public final C0859t getCanvasHolder() {
        return this.b;
    }

    @NotNull
    public final View getOwnerView() {
        return this.a;
    }

    @Override // android.view.View
    public final boolean hasOverlappingRendering() {
        return this.f;
    }

    @Override // android.view.View
    public final void invalidate() {
        if (this.d) {
            return;
        }
        this.d = true;
        super.invalidate();
    }

    @Override // android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
    }

    public final void setCanUseCompositingLayer$ui_graphics_release(boolean z) {
        if (this.f != z) {
            this.f = z;
            invalidate();
        }
    }

    public final void setInvalidated(boolean z) {
        this.d = z;
    }
}
