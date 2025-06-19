package androidx.compose.ui.draganddrop;

import android.graphics.Canvas;
import android.graphics.Point;
import android.view.View;
import androidx.compose.ui.graphics.AbstractC0845e;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.unit.k;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class a extends View.DragShadowBuilder {
    public final androidx.compose.ui.unit.c a;
    public final long b;
    public final Function1 c;

    public a(androidx.compose.ui.unit.c cVar, long j, Function1 function1) {
        this.a = cVar;
        this.b = j;
        this.c = function1;
    }

    @Override // android.view.View.DragShadowBuilder
    public final void onDrawShadow(Canvas canvas) {
        androidx.compose.ui.graphics.drawscope.b bVar = new androidx.compose.ui.graphics.drawscope.b();
        k kVar = k.a;
        Canvas canvas2 = AbstractC0845e.a;
        C0844d c0844d = new C0844d();
        c0844d.a = canvas;
        androidx.compose.ui.graphics.drawscope.a aVar = bVar.a;
        androidx.compose.ui.unit.b bVar2 = aVar.a;
        k kVar2 = aVar.b;
        InterfaceC0858s interfaceC0858s = aVar.c;
        long j = aVar.d;
        aVar.a = this.a;
        aVar.b = kVar;
        aVar.c = c0844d;
        aVar.d = this.b;
        c0844d.e();
        this.c.invoke(bVar);
        c0844d.q();
        aVar.a = bVar2;
        aVar.b = kVar2;
        aVar.c = interfaceC0858s;
        aVar.d = j;
    }

    @Override // android.view.View.DragShadowBuilder
    public final void onProvideShadowMetrics(Point point, Point point2) {
        long j = this.b;
        float fD = androidx.compose.ui.geometry.e.d(j);
        androidx.compose.ui.unit.c cVar = this.a;
        point.set(cVar.m0(fD / cVar.a()), cVar.m0(androidx.compose.ui.geometry.e.b(j) / cVar.a()));
        point2.set(point.x / 2, point.y / 2);
    }
}
