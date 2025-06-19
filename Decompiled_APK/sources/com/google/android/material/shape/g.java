package com.google.android.material.shape;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.os.Looper;
import android.util.AttributeSet;
import android.util.Log;
import com.google.android.gms.internal.ads.C2538qn;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.BitSet;
import java.util.Objects;

/* loaded from: classes2.dex */
public class g extends Drawable implements s {
    public static final Paint x;
    public f a;
    public final r[] b;
    public final r[] c;
    public final BitSet d;
    public boolean e;
    public final Matrix f;
    public final Path g;
    public final Path h;
    public final RectF i;
    public final RectF j;
    public final Region k;
    public final Region l;
    public j m;
    public final Paint n;
    public final Paint o;
    public final com.google.android.material.shadow.a p;
    public final androidx.webkit.internal.p q;
    public final C2538qn r;
    public PorterDuffColorFilter s;
    public PorterDuffColorFilter t;
    public int u;
    public final RectF v;
    public boolean w;

    static {
        Paint paint = new Paint(1);
        x = paint;
        paint.setColor(-1);
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.DST_OUT));
    }

    public g() {
        this(new j());
    }

    public final void b(RectF rectF, Path path) {
        f fVar = this.a;
        this.r.a(fVar.a, fVar.i, rectF, this.q, path);
        if (this.a.h != 1.0f) {
            Matrix matrix = this.f;
            matrix.reset();
            float f = this.a.h;
            matrix.setScale(f, f, rectF.width() / 2.0f, rectF.height() / 2.0f);
            path.transform(matrix);
        }
        path.computeBounds(this.v, true);
    }

    public final int c(int i) {
        f fVar = this.a;
        float f = fVar.m + DefinitionKt.NO_Float_VALUE + fVar.l;
        com.google.android.material.elevation.a aVar = fVar.b;
        return aVar != null ? aVar.a(f, i) : i;
    }

    public final void d(Canvas canvas) {
        if (this.d.cardinality() > 0) {
            Log.w("g", "Compatibility shadow requested but can't be drawn for all operations in this shape.");
        }
        int i = this.a.p;
        Path path = this.g;
        com.google.android.material.shadow.a aVar = this.p;
        if (i != 0) {
            canvas.drawPath(path, aVar.a);
        }
        for (int i2 = 0; i2 < 4; i2++) {
            r rVar = this.b[i2];
            int i3 = this.a.o;
            Matrix matrix = r.b;
            rVar.a(matrix, aVar, i3, canvas);
            this.c[i2].a(matrix, aVar, this.a.o, canvas);
        }
        if (this.w) {
            f fVar = this.a;
            int iSin = (int) (Math.sin(Math.toRadians(fVar.q)) * fVar.p);
            int iH = h();
            canvas.translate(-iSin, -iH);
            canvas.drawPath(path, x);
            canvas.translate(iSin, iH);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00f4  */
    @Override // android.graphics.drawable.Drawable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void draw(android.graphics.Canvas r19) {
        /*
            Method dump skipped, instructions count: 447
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.shape.g.draw(android.graphics.Canvas):void");
    }

    public final void e(Canvas canvas, Paint paint, Path path, j jVar, RectF rectF) {
        if (!jVar.e(rectF)) {
            canvas.drawPath(path, paint);
        } else {
            float fA = jVar.f.a(rectF) * this.a.i;
            canvas.drawRoundRect(rectF, fA, fA, paint);
        }
    }

    public void f(Canvas canvas) {
        Paint paint = this.o;
        Path path = this.h;
        j jVar = this.m;
        RectF rectF = this.j;
        rectF.set(g());
        float strokeWidth = j() ? paint.getStrokeWidth() / 2.0f : DefinitionKt.NO_Float_VALUE;
        rectF.inset(strokeWidth, strokeWidth);
        e(canvas, paint, path, jVar, rectF);
    }

    public final RectF g() {
        RectF rectF = this.i;
        rectF.set(getBounds());
        return rectF;
    }

    @Override // android.graphics.drawable.Drawable
    public int getAlpha() {
        return this.a.k;
    }

    @Override // android.graphics.drawable.Drawable
    public final Drawable.ConstantState getConstantState() {
        return this.a;
    }

    @Override // android.graphics.drawable.Drawable
    public int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public void getOutline(Outline outline) {
        f fVar = this.a;
        if (fVar.n == 2) {
            return;
        }
        if (fVar.a.e(g())) {
            outline.setRoundRect(getBounds(), i() * this.a.i);
        } else {
            RectF rectFG = g();
            Path path = this.g;
            b(rectFG, path);
            Y3.k(outline, path);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean getPadding(Rect rect) {
        Rect rect2 = this.a.g;
        if (rect2 == null) {
            return super.getPadding(rect);
        }
        rect.set(rect2);
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public final Region getTransparentRegion() {
        Rect bounds = getBounds();
        Region region = this.k;
        region.set(bounds);
        RectF rectFG = g();
        Path path = this.g;
        b(rectFG, path);
        Region region2 = this.l;
        region2.setPath(path, region);
        region.op(region2, Region.Op.DIFFERENCE);
        return region;
    }

    public final int h() {
        f fVar = this.a;
        return (int) (Math.cos(Math.toRadians(fVar.q)) * fVar.p);
    }

    public final float i() {
        return this.a.a.e.a(g());
    }

    @Override // android.graphics.drawable.Drawable
    public final void invalidateSelf() {
        this.e = true;
        super.invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public boolean isStateful() {
        if (super.isStateful()) {
            return true;
        }
        ColorStateList colorStateList = this.a.e;
        if (colorStateList != null && colorStateList.isStateful()) {
            return true;
        }
        this.a.getClass();
        ColorStateList colorStateList2 = this.a.d;
        if (colorStateList2 != null && colorStateList2.isStateful()) {
            return true;
        }
        ColorStateList colorStateList3 = this.a.c;
        return colorStateList3 != null && colorStateList3.isStateful();
    }

    public final boolean j() {
        Paint.Style style = this.a.r;
        return (style == Paint.Style.FILL_AND_STROKE || style == Paint.Style.STROKE) && this.o.getStrokeWidth() > DefinitionKt.NO_Float_VALUE;
    }

    public final void k(Context context) {
        this.a.b = new com.google.android.material.elevation.a(context);
        u();
    }

    public final void l(float f) {
        f fVar = this.a;
        if (fVar.m != f) {
            fVar.m = f;
            u();
        }
    }

    public final void m(ColorStateList colorStateList) {
        f fVar = this.a;
        if (fVar.c != colorStateList) {
            fVar.c = colorStateList;
            onStateChange(getState());
        }
    }

    @Override // android.graphics.drawable.Drawable
    public Drawable mutate() {
        this.a = new f(this.a);
        return this;
    }

    public final void n(float f) {
        f fVar = this.a;
        if (fVar.i != f) {
            fVar.i = f;
            this.e = true;
            invalidateSelf();
        }
    }

    public final void o() {
        this.a.r = Paint.Style.FILL;
        super.invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void onBoundsChange(Rect rect) {
        this.e = true;
        super.onBoundsChange(rect);
    }

    @Override // android.graphics.drawable.Drawable, com.google.android.material.internal.m
    public boolean onStateChange(int[] iArr) {
        boolean z = s(iArr) || t();
        if (z) {
            invalidateSelf();
        }
        return z;
    }

    public final void p() {
        this.p.a(-12303292);
        this.a.getClass();
        super.invalidateSelf();
    }

    public final void q(int i) {
        f fVar = this.a;
        if (fVar.n != i) {
            fVar.n = i;
            super.invalidateSelf();
        }
    }

    public final void r(ColorStateList colorStateList) {
        f fVar = this.a;
        if (fVar.d != colorStateList) {
            fVar.d = colorStateList;
            onStateChange(getState());
        }
    }

    public final boolean s(int[] iArr) {
        boolean z;
        Paint paint;
        int color;
        int colorForState;
        Paint paint2;
        int color2;
        int colorForState2;
        if (this.a.c == null || color2 == (colorForState2 = this.a.c.getColorForState(iArr, (color2 = (paint2 = this.n).getColor())))) {
            z = false;
        } else {
            paint2.setColor(colorForState2);
            z = true;
        }
        if (this.a.d == null || color == (colorForState = this.a.d.getColorForState(iArr, (color = (paint = this.o).getColor())))) {
            return z;
        }
        paint.setColor(colorForState);
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public void setAlpha(int i) {
        f fVar = this.a;
        if (fVar.k != i) {
            fVar.k = i;
            super.invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public void setColorFilter(ColorFilter colorFilter) {
        this.a.getClass();
        super.invalidateSelf();
    }

    @Override // com.google.android.material.shape.s
    public final void setShapeAppearanceModel(j jVar) {
        this.a.a = jVar;
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setTint(int i) {
        setTintList(ColorStateList.valueOf(i));
    }

    @Override // android.graphics.drawable.Drawable
    public void setTintList(ColorStateList colorStateList) {
        this.a.e = colorStateList;
        t();
        super.invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public void setTintMode(PorterDuff.Mode mode) {
        f fVar = this.a;
        if (fVar.f != mode) {
            fVar.f = mode;
            t();
            super.invalidateSelf();
        }
    }

    public final boolean t() {
        PorterDuffColorFilter porterDuffColorFilter;
        PorterDuffColorFilter porterDuffColorFilter2 = this.s;
        PorterDuffColorFilter porterDuffColorFilter3 = this.t;
        f fVar = this.a;
        ColorStateList colorStateList = fVar.e;
        PorterDuff.Mode mode = fVar.f;
        Paint paint = this.n;
        if (colorStateList == null || mode == null) {
            int color = paint.getColor();
            int iC = c(color);
            this.u = iC;
            porterDuffColorFilter = iC != color ? new PorterDuffColorFilter(iC, PorterDuff.Mode.SRC_IN) : null;
        } else {
            int iC2 = c(colorStateList.getColorForState(getState(), 0));
            this.u = iC2;
            porterDuffColorFilter = new PorterDuffColorFilter(iC2, mode);
        }
        this.s = porterDuffColorFilter;
        this.a.getClass();
        this.t = null;
        this.a.getClass();
        return (Objects.equals(porterDuffColorFilter2, this.s) && Objects.equals(porterDuffColorFilter3, this.t)) ? false : true;
    }

    public final void u() {
        f fVar = this.a;
        float f = fVar.m + DefinitionKt.NO_Float_VALUE;
        fVar.o = (int) Math.ceil(0.75f * f);
        this.a.p = (int) Math.ceil(f * 0.25f);
        t();
        super.invalidateSelf();
    }

    public g(Context context, AttributeSet attributeSet, int i, int i2) {
        this(j.b(context, attributeSet, i, i2).a());
    }

    public g(j jVar) {
        this(new f(jVar));
    }

    public g(f fVar) {
        C2538qn c2538qn;
        this.b = new r[4];
        this.c = new r[4];
        this.d = new BitSet(8);
        this.f = new Matrix();
        this.g = new Path();
        this.h = new Path();
        this.i = new RectF();
        this.j = new RectF();
        this.k = new Region();
        this.l = new Region();
        Paint paint = new Paint(1);
        this.n = paint;
        Paint paint2 = new Paint(1);
        this.o = paint2;
        this.p = new com.google.android.material.shadow.a();
        if (Looper.getMainLooper().getThread() == Thread.currentThread()) {
            c2538qn = k.a;
        } else {
            c2538qn = new C2538qn();
        }
        this.r = c2538qn;
        this.v = new RectF();
        this.w = true;
        this.a = fVar;
        paint2.setStyle(Paint.Style.STROKE);
        paint.setStyle(Paint.Style.FILL);
        t();
        s(getState());
        this.q = new androidx.webkit.internal.p(this, 23);
    }
}
