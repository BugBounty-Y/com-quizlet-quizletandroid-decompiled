package androidx.compose.ui.graphics;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.Region;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.InvocationTargetException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.graphics.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0844d implements InterfaceC0858s {
    public Canvas a = AbstractC0845e.a;
    public Rect b;
    public Rect c;

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void a(float f, float f2) {
        this.a.scale(f, f2);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void b(float f) {
        this.a.rotate(f);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void c(C0848h c0848h, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawBitmap(F.l(c0848h), androidx.compose.ui.geometry.b.d(0L), androidx.compose.ui.geometry.b.e(0L), (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void d(O o, com.google.android.gms.cloudmessaging.k kVar) {
        Canvas canvas = this.a;
        if (!(o instanceof C0850j)) {
            throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
        }
        canvas.drawPath(((C0850j) o).a, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void e() {
        this.a.save();
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void f() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        F.o(this.a, false);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void g(androidx.compose.ui.geometry.c cVar, com.google.android.gms.cloudmessaging.k kVar) {
        Canvas canvas = this.a;
        Paint paint = (Paint) kVar.c;
        canvas.saveLayer(cVar.a, cVar.b, cVar.c, cVar.d, paint, 31);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void h(long j, long j2, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawLine(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.b.e(j2), (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void i(O o) {
        Canvas canvas = this.a;
        if (!(o instanceof C0850j)) {
            throw new UnsupportedOperationException("Unable to obtain android.graphics.Path");
        }
        canvas.clipPath(((C0850j) o).a, Region.Op.INTERSECT);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void j(float[] fArr) {
        int i = 0;
        while (i < 4) {
            int i2 = 0;
            while (i2 < 4) {
                if (fArr[(i * 4) + i2] != (i == i2 ? 1.0f : DefinitionKt.NO_Float_VALUE)) {
                    Matrix matrix = new Matrix();
                    F.t(matrix, fArr);
                    this.a.concat(matrix);
                    return;
                }
                i2++;
            }
            i++;
        }
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void l(float f, float f2, float f3, float f4, float f5, float f6, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawRoundRect(f, f2, f3, f4, f5, f6, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void m(float f, float f2, float f3, float f4, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawRect(f, f2, f3, f4, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void n(float f, long j, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawCircle(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), f, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void o(float f, float f2, float f3, float f4, int i) {
        this.a.clipRect(f, f2, f3, f4, i == 0 ? Region.Op.DIFFERENCE : Region.Op.INTERSECT);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void p(float f, float f2) {
        this.a.translate(f, f2);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void q() {
        this.a.restore();
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void r(C0848h c0848h, long j, long j2, long j3, com.google.android.gms.cloudmessaging.k kVar) {
        if (this.b == null) {
            this.b = new Rect();
            this.c = new Rect();
        }
        Canvas canvas = this.a;
        Bitmap bitmapL = F.l(c0848h);
        Rect rect = this.b;
        Intrinsics.d(rect);
        int i = (int) (j >> 32);
        rect.left = i;
        int i2 = (int) (j & 4294967295L);
        rect.top = i2;
        rect.right = i + ((int) (j2 >> 32));
        rect.bottom = i2 + ((int) (j2 & 4294967295L));
        Unit unit = Unit.a;
        Rect rect2 = this.c;
        Intrinsics.d(rect2);
        int i3 = (int) 0;
        rect2.left = i3;
        int i4 = (int) 0;
        rect2.top = i4;
        rect2.right = i3 + ((int) (j3 >> 32));
        rect2.bottom = i4 + ((int) (4294967295L & j3));
        canvas.drawBitmap(bitmapL, rect, rect2, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void s(float f, float f2, float f3, float f4, float f5, float f6, com.google.android.gms.cloudmessaging.k kVar) {
        this.a.drawArc(f, f2, f3, f4, f5, f6, false, (Paint) kVar.c);
    }

    @Override // androidx.compose.ui.graphics.InterfaceC0858s
    public final void t() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        F.o(this.a, true);
    }
}
