package com.google.android.material.chip;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Outline;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PointF;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.shapes.OvalShape;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.material.internal.m;
import com.google.android.material.internal.n;
import com.google.android.material.internal.p;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class f extends com.google.android.material.shape.g implements Drawable.Callback, m {
    public static final int[] Q1 = {R.attr.state_enabled};
    public static final ShapeDrawable R1 = new ShapeDrawable(new OvalShape());
    public float A;
    public int A1;
    public float B;
    public int B1;
    public ColorStateList C;
    public boolean C1;
    public float D;
    public int D1;
    public ColorStateList E;
    public int E1;
    public CharSequence F;
    public ColorFilter F1;
    public boolean G;
    public PorterDuffColorFilter G1;
    public Drawable H;
    public ColorStateList H1;
    public ColorStateList I;
    public PorterDuff.Mode I1;
    public float J;
    public int[] J1;
    public boolean K;
    public ColorStateList K1;
    public boolean L;
    public WeakReference L1;
    public Drawable M;
    public TextUtils.TruncateAt M1;
    public boolean N1;
    public int O1;
    public boolean P1;
    public RippleDrawable V;
    public ColorStateList W;
    public float X;
    public SpannableStringBuilder Y;
    public boolean Z;
    public boolean c1;
    public Drawable d1;
    public ColorStateList e1;
    public com.google.android.material.animation.f f1;
    public com.google.android.material.animation.f g1;
    public float h1;
    public float i1;
    public float j1;
    public float k1;
    public float l1;
    public float m1;
    public float n1;
    public float o1;
    public final Context p1;
    public final Paint q1;
    public final Paint.FontMetrics r1;
    public final RectF s1;
    public final PointF t1;
    public final Path u1;
    public final n v1;
    public int w1;
    public int x1;
    public ColorStateList y;
    public int y1;
    public ColorStateList z;
    public int z1;

    public f(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action);
        this.B = -1.0f;
        this.q1 = new Paint(1);
        this.r1 = new Paint.FontMetrics();
        this.s1 = new RectF();
        this.t1 = new PointF();
        this.u1 = new Path();
        this.E1 = 255;
        this.I1 = PorterDuff.Mode.SRC_IN;
        this.L1 = new WeakReference(null);
        k(context);
        this.p1 = context;
        n nVar = new n(this);
        this.v1 = nVar;
        this.F = "";
        nVar.a.density = context.getResources().getDisplayMetrics().density;
        int[] iArr = Q1;
        setState(iArr);
        if (!Arrays.equals(this.J1, iArr)) {
            this.J1 = iArr;
            if (a0()) {
                D(getState(), iArr);
            }
        }
        this.N1 = true;
        int[] iArr2 = com.google.android.material.ripple.a.a;
        R1.setTint(-1);
    }

    public static boolean A(ColorStateList colorStateList) {
        return colorStateList != null && colorStateList.isStateful();
    }

    public static boolean B(Drawable drawable) {
        return drawable != null && drawable.isStateful();
    }

    public static void b0(Drawable drawable) {
        if (drawable != null) {
            drawable.setCallback(null);
        }
    }

    public final void C() {
        e eVar = (e) this.L1.get();
        if (eVar != null) {
            Chip chip = (Chip) eVar;
            chip.b(chip.q);
            chip.requestLayout();
            chip.invalidateOutline();
        }
    }

    public final boolean D(int[] iArr, int[] iArr2) {
        boolean z;
        boolean z2;
        ColorStateList colorStateList;
        boolean state = true;
        boolean zOnStateChange = super.onStateChange(iArr);
        ColorStateList colorStateList2 = this.y;
        int iC = c(colorStateList2 != null ? colorStateList2.getColorForState(iArr, this.w1) : 0);
        if (this.w1 != iC) {
            this.w1 = iC;
            zOnStateChange = true;
        }
        ColorStateList colorStateList3 = this.z;
        int iC2 = c(colorStateList3 != null ? colorStateList3.getColorForState(iArr, this.x1) : 0);
        if (this.x1 != iC2) {
            this.x1 = iC2;
            zOnStateChange = true;
        }
        int iB = androidx.core.graphics.d.b(iC2, iC);
        if ((this.y1 != iB) | (this.a.c == null)) {
            this.y1 = iB;
            m(ColorStateList.valueOf(iB));
            zOnStateChange = true;
        }
        ColorStateList colorStateList4 = this.C;
        int colorForState = colorStateList4 != null ? colorStateList4.getColorForState(iArr, this.z1) : 0;
        if (this.z1 != colorForState) {
            this.z1 = colorForState;
            zOnStateChange = true;
        }
        int colorForState2 = (this.K1 == null || !com.google.android.material.ripple.a.c(iArr)) ? 0 : this.K1.getColorForState(iArr, this.A1);
        if (this.A1 != colorForState2) {
            this.A1 = colorForState2;
        }
        com.google.android.material.resources.e eVar = this.v1.g;
        int colorForState3 = (eVar == null || (colorStateList = eVar.j) == null) ? 0 : colorStateList.getColorForState(iArr, this.B1);
        if (this.B1 != colorForState3) {
            this.B1 = colorForState3;
            zOnStateChange = true;
        }
        int[] state2 = getState();
        if (state2 == null) {
            z = false;
        } else {
            int length = state2.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                if (state2[i] != 16842912) {
                    i++;
                } else if (this.Z) {
                    z = true;
                }
            }
            z = false;
        }
        if (this.C1 == z || this.d1 == null) {
            z2 = false;
        } else {
            float fX = x();
            this.C1 = z;
            if (fX != x()) {
                zOnStateChange = true;
                z2 = true;
            } else {
                zOnStateChange = true;
                z2 = false;
            }
        }
        ColorStateList colorStateList5 = this.H1;
        int colorForState4 = colorStateList5 != null ? colorStateList5.getColorForState(iArr, this.D1) : 0;
        if (this.D1 != colorForState4) {
            this.D1 = colorForState4;
            ColorStateList colorStateList6 = this.H1;
            PorterDuff.Mode mode = this.I1;
            this.G1 = (colorStateList6 == null || mode == null) ? null : new PorterDuffColorFilter(colorStateList6.getColorForState(getState(), 0), mode);
        } else {
            state = zOnStateChange;
        }
        if (B(this.H)) {
            state |= this.H.setState(iArr);
        }
        if (B(this.d1)) {
            state |= this.d1.setState(iArr);
        }
        if (B(this.M)) {
            int[] iArr3 = new int[iArr.length + iArr2.length];
            System.arraycopy(iArr, 0, iArr3, 0, iArr.length);
            System.arraycopy(iArr2, 0, iArr3, iArr.length, iArr2.length);
            state |= this.M.setState(iArr3);
        }
        int[] iArr4 = com.google.android.material.ripple.a.a;
        if (B(this.V)) {
            state |= this.V.setState(iArr2);
        }
        if (state) {
            invalidateSelf();
        }
        if (z2) {
            C();
        }
        return state;
    }

    public final void E(boolean z) {
        if (this.Z != z) {
            this.Z = z;
            float fX = x();
            if (!z && this.C1) {
                this.C1 = false;
            }
            float fX2 = x();
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void F(Drawable drawable) {
        if (this.d1 != drawable) {
            float fX = x();
            this.d1 = drawable;
            float fX2 = x();
            b0(this.d1);
            v(this.d1);
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void G(ColorStateList colorStateList) {
        Drawable drawable;
        if (this.e1 != colorStateList) {
            this.e1 = colorStateList;
            if (this.c1 && (drawable = this.d1) != null && this.Z) {
                drawable.setTintList(colorStateList);
            }
            onStateChange(getState());
        }
    }

    public final void H(boolean z) {
        if (this.c1 != z) {
            boolean zY = Y();
            this.c1 = z;
            boolean zY2 = Y();
            if (zY != zY2) {
                if (zY2) {
                    v(this.d1);
                } else {
                    b0(this.d1);
                }
                invalidateSelf();
                C();
            }
        }
    }

    public final void I(float f) {
        if (this.B != f) {
            this.B = f;
            G4 g4F = this.a.a.f();
            g4F.e = new com.google.android.material.shape.a(f);
            g4F.f = new com.google.android.material.shape.a(f);
            g4F.g = new com.google.android.material.shape.a(f);
            g4F.h = new com.google.android.material.shape.a(f);
            setShapeAppearanceModel(g4F.a());
        }
    }

    public final void J(Drawable drawable) {
        Drawable drawable2 = this.H;
        Drawable drawableE = drawable2 != null ? AbstractC3179j6.e(drawable2) : null;
        if (drawableE != drawable) {
            float fX = x();
            this.H = drawable != null ? drawable.mutate() : null;
            float fX2 = x();
            b0(drawableE);
            if (Z()) {
                v(this.H);
            }
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void K(float f) {
        if (this.J != f) {
            float fX = x();
            this.J = f;
            float fX2 = x();
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void L(ColorStateList colorStateList) {
        this.K = true;
        if (this.I != colorStateList) {
            this.I = colorStateList;
            if (Z()) {
                this.H.setTintList(colorStateList);
            }
            onStateChange(getState());
        }
    }

    public final void M(boolean z) {
        if (this.G != z) {
            boolean Z = Z();
            this.G = z;
            boolean Z2 = Z();
            if (Z != Z2) {
                if (Z2) {
                    v(this.H);
                } else {
                    b0(this.H);
                }
                invalidateSelf();
                C();
            }
        }
    }

    public final void N(ColorStateList colorStateList) {
        if (this.C != colorStateList) {
            this.C = colorStateList;
            if (this.P1) {
                r(colorStateList);
            }
            onStateChange(getState());
        }
    }

    public final void O(float f) {
        if (this.D != f) {
            this.D = f;
            this.q1.setStrokeWidth(f);
            if (this.P1) {
                this.a.j = f;
                invalidateSelf();
            }
            invalidateSelf();
        }
    }

    public final void P(Drawable drawable) {
        Drawable drawable2 = this.M;
        Drawable drawableE = drawable2 != null ? AbstractC3179j6.e(drawable2) : null;
        if (drawableE != drawable) {
            float fY = y();
            this.M = drawable != null ? drawable.mutate() : null;
            int[] iArr = com.google.android.material.ripple.a.a;
            this.V = new RippleDrawable(com.google.android.material.ripple.a.b(this.E), this.M, R1);
            float fY2 = y();
            b0(drawableE);
            if (a0()) {
                v(this.M);
            }
            invalidateSelf();
            if (fY != fY2) {
                C();
            }
        }
    }

    public final void Q(float f) {
        if (this.n1 != f) {
            this.n1 = f;
            invalidateSelf();
            if (a0()) {
                C();
            }
        }
    }

    public final void R(float f) {
        if (this.X != f) {
            this.X = f;
            invalidateSelf();
            if (a0()) {
                C();
            }
        }
    }

    public final void S(float f) {
        if (this.m1 != f) {
            this.m1 = f;
            invalidateSelf();
            if (a0()) {
                C();
            }
        }
    }

    public final void T(ColorStateList colorStateList) {
        if (this.W != colorStateList) {
            this.W = colorStateList;
            if (a0()) {
                this.M.setTintList(colorStateList);
            }
            onStateChange(getState());
        }
    }

    public final void U(boolean z) {
        if (this.L != z) {
            boolean zA0 = a0();
            this.L = z;
            boolean zA02 = a0();
            if (zA0 != zA02) {
                if (zA02) {
                    v(this.M);
                } else {
                    b0(this.M);
                }
                invalidateSelf();
                C();
            }
        }
    }

    public final void V(float f) {
        if (this.j1 != f) {
            float fX = x();
            this.j1 = f;
            float fX2 = x();
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void W(float f) {
        if (this.i1 != f) {
            float fX = x();
            this.i1 = f;
            float fX2 = x();
            invalidateSelf();
            if (fX != fX2) {
                C();
            }
        }
    }

    public final void X(ColorStateList colorStateList) {
        if (this.E != colorStateList) {
            this.E = colorStateList;
            this.K1 = null;
            onStateChange(getState());
        }
    }

    public final boolean Y() {
        return this.c1 && this.d1 != null && this.C1;
    }

    public final boolean Z() {
        return this.G && this.H != null;
    }

    @Override // com.google.android.material.internal.m
    public final void a() {
        C();
        invalidateSelf();
    }

    public final boolean a0() {
        return this.L && this.M != null;
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        int i;
        Canvas canvas2;
        int iSaveLayerAlpha;
        float f;
        int i2;
        Rect bounds = getBounds();
        if (bounds.isEmpty() || (i = this.E1) == 0) {
            return;
        }
        if (i < 255) {
            canvas2 = canvas;
            iSaveLayerAlpha = canvas2.saveLayerAlpha(bounds.left, bounds.top, bounds.right, bounds.bottom, i);
        } else {
            canvas2 = canvas;
            iSaveLayerAlpha = 0;
        }
        boolean z = this.P1;
        Paint paint = this.q1;
        RectF rectF = this.s1;
        if (!z) {
            paint.setColor(this.w1);
            paint.setStyle(Paint.Style.FILL);
            rectF.set(bounds);
            canvas2.drawRoundRect(rectF, z(), z(), paint);
        }
        if (!this.P1) {
            paint.setColor(this.x1);
            paint.setStyle(Paint.Style.FILL);
            ColorFilter colorFilter = this.F1;
            if (colorFilter == null) {
                colorFilter = this.G1;
            }
            paint.setColorFilter(colorFilter);
            rectF.set(bounds);
            canvas2.drawRoundRect(rectF, z(), z(), paint);
        }
        if (this.P1) {
            super.draw(canvas);
        }
        if (this.D > DefinitionKt.NO_Float_VALUE && !this.P1) {
            paint.setColor(this.z1);
            paint.setStyle(Paint.Style.STROKE);
            if (!this.P1) {
                ColorFilter colorFilter2 = this.F1;
                if (colorFilter2 == null) {
                    colorFilter2 = this.G1;
                }
                paint.setColorFilter(colorFilter2);
            }
            float f2 = bounds.left;
            float f3 = this.D / 2.0f;
            rectF.set(f2 + f3, bounds.top + f3, bounds.right - f3, bounds.bottom - f3);
            float f4 = this.B - (this.D / 2.0f);
            canvas2.drawRoundRect(rectF, f4, f4, paint);
        }
        paint.setColor(this.A1);
        paint.setStyle(Paint.Style.FILL);
        rectF.set(bounds);
        if (this.P1) {
            RectF rectF2 = new RectF(bounds);
            Path path = this.u1;
            com.google.android.material.shape.f fVar = this.a;
            this.r.a(fVar.a, fVar.i, rectF2, this.q, path);
            e(canvas2, paint, path, this.a.a, g());
        } else {
            canvas2.drawRoundRect(rectF, z(), z(), paint);
        }
        if (Z()) {
            w(bounds, rectF);
            float f5 = rectF.left;
            float f6 = rectF.top;
            canvas2.translate(f5, f6);
            this.H.setBounds(0, 0, (int) rectF.width(), (int) rectF.height());
            this.H.draw(canvas2);
            canvas2.translate(-f5, -f6);
        }
        if (Y()) {
            w(bounds, rectF);
            float f7 = rectF.left;
            float f8 = rectF.top;
            canvas2.translate(f7, f8);
            this.d1.setBounds(0, 0, (int) rectF.width(), (int) rectF.height());
            this.d1.draw(canvas2);
            canvas2.translate(-f7, -f8);
        }
        if (this.N1 && this.F != null) {
            PointF pointF = this.t1;
            pointF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            Paint.Align align = Paint.Align.LEFT;
            CharSequence charSequence = this.F;
            n nVar = this.v1;
            if (charSequence != null) {
                float fX = x() + this.h1 + this.k1;
                if (getLayoutDirection() == 0) {
                    pointF.x = bounds.left + fX;
                } else {
                    pointF.x = bounds.right - fX;
                    align = Paint.Align.RIGHT;
                }
                float fCenterY = bounds.centerY();
                TextPaint textPaint = nVar.a;
                Paint.FontMetrics fontMetrics = this.r1;
                textPaint.getFontMetrics(fontMetrics);
                pointF.y = fCenterY - ((fontMetrics.descent + fontMetrics.ascent) / 2.0f);
            }
            rectF.setEmpty();
            if (this.F != null) {
                float fX2 = x() + this.h1 + this.k1;
                float fY = y() + this.o1 + this.l1;
                if (getLayoutDirection() == 0) {
                    rectF.left = bounds.left + fX2;
                    rectF.right = bounds.right - fY;
                } else {
                    rectF.left = bounds.left + fY;
                    rectF.right = bounds.right - fX2;
                }
                rectF.top = bounds.top;
                rectF.bottom = bounds.bottom;
            }
            com.google.android.material.resources.e eVar = nVar.g;
            TextPaint textPaint2 = nVar.a;
            if (eVar != null) {
                textPaint2.drawableState = getState();
                nVar.g.e(this.p1, textPaint2, nVar.b);
            }
            textPaint2.setTextAlign(align);
            String string = this.F.toString();
            if (nVar.e) {
                nVar.a(string);
                f = nVar.c;
            } else {
                f = nVar.c;
            }
            boolean z2 = Math.round(f) > Math.round(rectF.width());
            if (z2) {
                int iSave = canvas2.save();
                canvas2.clipRect(rectF);
                i2 = iSave;
            } else {
                i2 = 0;
            }
            CharSequence charSequenceEllipsize = this.F;
            if (z2 && this.M1 != null) {
                charSequenceEllipsize = TextUtils.ellipsize(charSequenceEllipsize, textPaint2, rectF.width(), this.M1);
            }
            canvas.drawText(charSequenceEllipsize, 0, charSequenceEllipsize.length(), pointF.x, pointF.y, textPaint2);
            canvas2 = canvas;
            if (z2) {
                canvas2.restoreToCount(i2);
            }
        }
        if (a0()) {
            rectF.setEmpty();
            if (a0()) {
                float f9 = this.o1 + this.n1;
                if (getLayoutDirection() == 0) {
                    float f10 = bounds.right - f9;
                    rectF.right = f10;
                    rectF.left = f10 - this.X;
                } else {
                    float f11 = bounds.left + f9;
                    rectF.left = f11;
                    rectF.right = f11 + this.X;
                }
                float fExactCenterY = bounds.exactCenterY();
                float f12 = this.X;
                float f13 = fExactCenterY - (f12 / 2.0f);
                rectF.top = f13;
                rectF.bottom = f13 + f12;
            }
            float f14 = rectF.left;
            float f15 = rectF.top;
            canvas2.translate(f14, f15);
            this.M.setBounds(0, 0, (int) rectF.width(), (int) rectF.height());
            int[] iArr = com.google.android.material.ripple.a.a;
            this.V.setBounds(this.M.getBounds());
            this.V.jumpToCurrentState();
            this.V.draw(canvas2);
            canvas2.translate(-f14, -f15);
        }
        if (this.E1 < 255) {
            canvas2.restoreToCount(iSaveLayerAlpha);
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final int getAlpha() {
        return this.E1;
    }

    @Override // android.graphics.drawable.Drawable
    public final ColorFilter getColorFilter() {
        return this.F1;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicHeight() {
        return (int) this.A;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicWidth() {
        float f;
        float fX = x() + this.h1 + this.k1;
        String string = this.F.toString();
        n nVar = this.v1;
        if (nVar.e) {
            nVar.a(string);
            f = nVar.c;
        } else {
            f = nVar.c;
        }
        return Math.min(Math.round(y() + f + fX + this.l1 + this.o1), this.O1);
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void getOutline(Outline outline) {
        Outline outline2;
        if (this.P1) {
            super.getOutline(outline);
            return;
        }
        Rect bounds = getBounds();
        if (bounds.isEmpty()) {
            outline2 = outline;
            outline2.setRoundRect(0, 0, getIntrinsicWidth(), (int) this.A, this.B);
        } else {
            outline.setRoundRect(bounds, this.B);
            outline2 = outline;
        }
        outline2.setAlpha(this.E1 / 255.0f);
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void invalidateDrawable(Drawable drawable) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.invalidateDrawable(this);
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final boolean isStateful() {
        ColorStateList colorStateList;
        if (A(this.y) || A(this.z) || A(this.C)) {
            return true;
        }
        com.google.android.material.resources.e eVar = this.v1.g;
        if (eVar == null || (colorStateList = eVar.j) == null || !colorStateList.isStateful()) {
            return (this.c1 && this.d1 != null && this.Z) || B(this.H) || B(this.d1) || A(this.H1);
        }
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean onLayoutDirectionChanged(int i) {
        boolean zOnLayoutDirectionChanged = super.onLayoutDirectionChanged(i);
        if (Z()) {
            zOnLayoutDirectionChanged |= this.H.setLayoutDirection(i);
        }
        if (Y()) {
            zOnLayoutDirectionChanged |= this.d1.setLayoutDirection(i);
        }
        if (a0()) {
            zOnLayoutDirectionChanged |= this.M.setLayoutDirection(i);
        }
        if (!zOnLayoutDirectionChanged) {
            return true;
        }
        invalidateSelf();
        return true;
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean onLevelChange(int i) {
        boolean zOnLevelChange = super.onLevelChange(i);
        if (Z()) {
            zOnLevelChange |= this.H.setLevel(i);
        }
        if (Y()) {
            zOnLevelChange |= this.d1.setLevel(i);
        }
        if (a0()) {
            zOnLevelChange |= this.M.setLevel(i);
        }
        if (zOnLevelChange) {
            invalidateSelf();
        }
        return zOnLevelChange;
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable, com.google.android.material.internal.m
    public final boolean onStateChange(int[] iArr) {
        if (this.P1) {
            super.onStateChange(iArr);
        }
        return D(iArr, this.J1);
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void scheduleDrawable(Drawable drawable, Runnable runnable, long j) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.scheduleDrawable(this, runnable, j);
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        if (this.E1 != i) {
            this.E1 = i;
            invalidateSelf();
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
        if (this.F1 != colorFilter) {
            this.F1 = colorFilter;
            invalidateSelf();
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void setTintList(ColorStateList colorStateList) {
        if (this.H1 != colorStateList) {
            this.H1 = colorStateList;
            onStateChange(getState());
        }
    }

    @Override // com.google.android.material.shape.g, android.graphics.drawable.Drawable
    public final void setTintMode(PorterDuff.Mode mode) {
        if (this.I1 != mode) {
            this.I1 = mode;
            ColorStateList colorStateList = this.H1;
            this.G1 = (colorStateList == null || mode == null) ? null : new PorterDuffColorFilter(colorStateList.getColorForState(getState(), 0), mode);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean setVisible(boolean z, boolean z2) {
        boolean visible = super.setVisible(z, z2);
        if (Z()) {
            visible |= this.H.setVisible(z, z2);
        }
        if (Y()) {
            visible |= this.d1.setVisible(z, z2);
        }
        if (a0()) {
            visible |= this.M.setVisible(z, z2);
        }
        if (visible) {
            invalidateSelf();
        }
        return visible;
    }

    @Override // android.graphics.drawable.Drawable.Callback
    public final void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        Drawable.Callback callback = getCallback();
        if (callback != null) {
            callback.unscheduleDrawable(this, runnable);
        }
    }

    public final void v(Drawable drawable) {
        if (drawable == null) {
            return;
        }
        drawable.setCallback(this);
        drawable.setLayoutDirection(getLayoutDirection());
        drawable.setLevel(getLevel());
        drawable.setVisible(isVisible(), false);
        if (drawable == this.M) {
            if (drawable.isStateful()) {
                drawable.setState(this.J1);
            }
            drawable.setTintList(this.W);
            return;
        }
        Drawable drawable2 = this.H;
        if (drawable == drawable2 && this.K) {
            drawable2.setTintList(this.I);
        }
        if (drawable.isStateful()) {
            drawable.setState(getState());
        }
    }

    public final void w(Rect rect, RectF rectF) {
        rectF.setEmpty();
        if (Z() || Y()) {
            float f = this.h1 + this.i1;
            Drawable drawable = this.C1 ? this.d1 : this.H;
            float intrinsicWidth = this.J;
            if (intrinsicWidth <= DefinitionKt.NO_Float_VALUE && drawable != null) {
                intrinsicWidth = drawable.getIntrinsicWidth();
            }
            if (getLayoutDirection() == 0) {
                float f2 = rect.left + f;
                rectF.left = f2;
                rectF.right = f2 + intrinsicWidth;
            } else {
                float f3 = rect.right - f;
                rectF.right = f3;
                rectF.left = f3 - intrinsicWidth;
            }
            Drawable drawable2 = this.C1 ? this.d1 : this.H;
            float fCeil = this.J;
            if (fCeil <= DefinitionKt.NO_Float_VALUE && drawable2 != null) {
                fCeil = (float) Math.ceil(p.g(this.p1, 24));
                if (drawable2.getIntrinsicHeight() <= fCeil) {
                    fCeil = drawable2.getIntrinsicHeight();
                }
            }
            float fExactCenterY = rect.exactCenterY() - (fCeil / 2.0f);
            rectF.top = fExactCenterY;
            rectF.bottom = fExactCenterY + fCeil;
        }
    }

    public final float x() {
        if (!Z() && !Y()) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = this.i1;
        Drawable drawable = this.C1 ? this.d1 : this.H;
        float intrinsicWidth = this.J;
        if (intrinsicWidth <= DefinitionKt.NO_Float_VALUE && drawable != null) {
            intrinsicWidth = drawable.getIntrinsicWidth();
        }
        return intrinsicWidth + f + this.j1;
    }

    public final float y() {
        return a0() ? this.m1 + this.X + this.n1 : DefinitionKt.NO_Float_VALUE;
    }

    public final float z() {
        return this.P1 ? i() : this.B;
    }
}
