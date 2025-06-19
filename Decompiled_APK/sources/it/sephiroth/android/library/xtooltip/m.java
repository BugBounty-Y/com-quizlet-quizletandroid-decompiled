package it.sephiroth.android.library.xtooltip;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Point;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends Drawable {
    public final RectF a;
    public final Path b;
    public final Point c = new Point();
    public final Rect d = new Rect();
    public final Paint e;
    public final Paint f;
    public final float g;
    public final float h;
    public Point i;
    public int j;
    public int k;
    public e l;

    public m(Context context, d dVar) {
        TypedArray typedArrayObtainStyledAttributes = context.getTheme().obtainStyledAttributes(null, b.a, dVar.f, dVar.e);
        this.h = typedArrayObtainStyledAttributes.getDimensionPixelSize(4, 4);
        int dimensionPixelSize = typedArrayObtainStyledAttributes.getDimensionPixelSize(10, 2);
        int color = typedArrayObtainStyledAttributes.getColor(3, 0);
        int color2 = typedArrayObtainStyledAttributes.getColor(9, 0);
        this.g = typedArrayObtainStyledAttributes.getFloat(2, 1.4f);
        typedArrayObtainStyledAttributes.recycle();
        this.a = new RectF();
        if (color != 0) {
            Paint paint = new Paint(1);
            this.e = paint;
            paint.setColor(color);
            paint.setStyle(Paint.Style.FILL);
        } else {
            this.e = null;
        }
        if (color2 != 0) {
            Paint paint2 = new Paint(1);
            this.f = paint2;
            paint2.setColor(color2);
            paint2.setStyle(Paint.Style.STROKE);
            paint2.setStrokeWidth(dimensionPixelSize);
        } else {
            this.f = null;
        }
        this.b = new Path();
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x01cb  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x01d6  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x01dc  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x021d  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x024b  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0279  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(android.graphics.Rect r26) {
        /*
            Method dump skipped, instructions count: 697
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: it.sephiroth.android.library.xtooltip.m.a(android.graphics.Rect):void");
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        Intrinsics.f(canvas, "canvas");
        Paint paint = this.e;
        Path path = this.b;
        if (paint != null) {
            canvas.drawPath(path, paint);
        }
        Paint paint2 = this.f;
        if (paint2 != null) {
            canvas.drawPath(path, paint2);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final int getAlpha() {
        Paint paint = this.e;
        if (paint != null) {
            return paint.getAlpha();
        }
        return 0;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public final void getOutline(Outline outline) {
        Intrinsics.f(outline, "outline");
        Rect rect = this.d;
        copyBounds(rect);
        int i = this.j;
        rect.inset(i, i);
        outline.setRoundRect(rect, this.h);
        if (getAlpha() < 255) {
            outline.setAlpha(DefinitionKt.NO_Float_VALUE);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void onBoundsChange(Rect bounds) {
        Intrinsics.f(bounds, "bounds");
        super.onBoundsChange(bounds);
        a(bounds);
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        Paint paint = this.e;
        if (paint != null) {
            paint.setAlpha(i);
        }
        Paint paint2 = this.f;
        if (paint2 != null) {
            paint2.setAlpha(i);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
    }
}
