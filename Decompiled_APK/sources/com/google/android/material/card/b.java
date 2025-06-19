package com.google.android.material.card;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.Checkable;
import androidx.annotation.NonNull;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.internal.p;
import com.google.android.material.shape.g;
import com.google.android.material.shape.j;
import com.google.android.material.shape.s;

/* loaded from: classes2.dex */
public class b extends CardView implements Checkable, s {
    public static final int[] l = {R.attr.state_checkable};
    public static final int[] m = {R.attr.state_checked};
    public static final int[] n = {com.quizlet.quizletandroid.R.attr.state_dragged};
    public final d h;
    public final boolean i;
    public boolean j;
    public boolean k;

    public b(Context context) {
        this(context, 0);
    }

    @NonNull
    private RectF getBoundsAsRectF() {
        RectF rectF = new RectF();
        rectF.set(this.h.c.getBounds());
        return rectF;
    }

    public final void f() {
        d dVar;
        RippleDrawable rippleDrawable;
        if (Build.VERSION.SDK_INT <= 26 || (rippleDrawable = (dVar = this.h).o) == null) {
            return;
        }
        Rect bounds = rippleDrawable.getBounds();
        int i = bounds.bottom;
        dVar.o.setBounds(bounds.left, bounds.top, bounds.right, i - 1);
        dVar.o.setBounds(bounds.left, bounds.top, bounds.right, i);
    }

    @Override // androidx.cardview.widget.CardView
    @NonNull
    public ColorStateList getCardBackgroundColor() {
        return this.h.c.a.c;
    }

    @NonNull
    public ColorStateList getCardForegroundColor() {
        return this.h.d.a.c;
    }

    public float getCardViewRadius() {
        return super.getRadius();
    }

    public Drawable getCheckedIcon() {
        return this.h.j;
    }

    public int getCheckedIconGravity() {
        return this.h.g;
    }

    public int getCheckedIconMargin() {
        return this.h.e;
    }

    public int getCheckedIconSize() {
        return this.h.f;
    }

    public ColorStateList getCheckedIconTint() {
        return this.h.l;
    }

    @Override // androidx.cardview.widget.CardView
    public int getContentPaddingBottom() {
        return this.h.b.bottom;
    }

    @Override // androidx.cardview.widget.CardView
    public int getContentPaddingLeft() {
        return this.h.b.left;
    }

    @Override // androidx.cardview.widget.CardView
    public int getContentPaddingRight() {
        return this.h.b.right;
    }

    @Override // androidx.cardview.widget.CardView
    public int getContentPaddingTop() {
        return this.h.b.top;
    }

    public float getProgress() {
        return this.h.c.a.i;
    }

    @Override // androidx.cardview.widget.CardView
    public float getRadius() {
        return this.h.c.i();
    }

    public ColorStateList getRippleColor() {
        return this.h.k;
    }

    @NonNull
    public j getShapeAppearanceModel() {
        return this.h.m;
    }

    @Deprecated
    public int getStrokeColor() {
        ColorStateList colorStateList = this.h.n;
        if (colorStateList == null) {
            return -1;
        }
        return colorStateList.getDefaultColor();
    }

    public ColorStateList getStrokeColorStateList() {
        return this.h.n;
    }

    public int getStrokeWidth() {
        return this.h.h;
    }

    @Override // android.widget.Checkable
    public final boolean isChecked() {
        return this.j;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        d dVar = this.h;
        dVar.k();
        AbstractC3466h4.b(this, dVar.c);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final int[] onCreateDrawableState(int i) {
        int[] iArrOnCreateDrawableState = super.onCreateDrawableState(i + 3);
        d dVar = this.h;
        if (dVar != null && dVar.s) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, l);
        }
        if (this.j) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, m);
        }
        if (this.k) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, n);
        }
        return iArrOnCreateDrawableState;
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        super.onInitializeAccessibilityEvent(accessibilityEvent);
        accessibilityEvent.setClassName("androidx.cardview.widget.CardView");
        accessibilityEvent.setChecked(this.j);
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName("androidx.cardview.widget.CardView");
        d dVar = this.h;
        accessibilityNodeInfo.setCheckable(dVar != null && dVar.s);
        accessibilityNodeInfo.setClickable(isClickable());
        accessibilityNodeInfo.setChecked(this.j);
    }

    @Override // androidx.cardview.widget.CardView, android.widget.FrameLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        this.h.e(getMeasuredWidth(), getMeasuredHeight());
    }

    @Override // android.view.View
    public void setBackground(Drawable drawable) {
        setBackgroundDrawable(drawable);
    }

    @Override // android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        if (this.i) {
            d dVar = this.h;
            if (!dVar.r) {
                Log.i("MaterialCardView", "Setting a custom background is not supported.");
                dVar.r = true;
            }
            super.setBackgroundDrawable(drawable);
        }
    }

    public void setBackgroundInternal(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
    }

    @Override // androidx.cardview.widget.CardView
    public void setCardBackgroundColor(ColorStateList colorStateList) {
        this.h.c.m(colorStateList);
    }

    @Override // androidx.cardview.widget.CardView
    public void setCardElevation(float f) {
        super.setCardElevation(f);
        d dVar = this.h;
        dVar.c.l(dVar.a.getCardElevation());
    }

    public void setCardForegroundColor(ColorStateList colorStateList) {
        g gVar = this.h.d;
        if (colorStateList == null) {
            colorStateList = ColorStateList.valueOf(0);
        }
        gVar.m(colorStateList);
    }

    public void setCheckable(boolean z) {
        this.h.s = z;
    }

    @Override // android.widget.Checkable
    public void setChecked(boolean z) {
        if (this.j != z) {
            toggle();
        }
    }

    public void setCheckedIcon(Drawable drawable) {
        this.h.g(drawable);
    }

    public void setCheckedIconGravity(int i) {
        d dVar = this.h;
        if (dVar.g != i) {
            dVar.g = i;
            b bVar = dVar.a;
            dVar.e(bVar.getMeasuredWidth(), bVar.getMeasuredHeight());
        }
    }

    public void setCheckedIconMargin(int i) {
        this.h.e = i;
    }

    public void setCheckedIconMarginResource(int i) {
        if (i != -1) {
            this.h.e = getResources().getDimensionPixelSize(i);
        }
    }

    public void setCheckedIconResource(int i) {
        this.h.g(com.facebook.appevents.g.f(getContext(), i));
    }

    public void setCheckedIconSize(int i) {
        this.h.f = i;
    }

    public void setCheckedIconSizeResource(int i) {
        if (i != 0) {
            this.h.f = getResources().getDimensionPixelSize(i);
        }
    }

    public void setCheckedIconTint(ColorStateList colorStateList) {
        d dVar = this.h;
        dVar.l = colorStateList;
        Drawable drawable = dVar.j;
        if (drawable != null) {
            drawable.setTintList(colorStateList);
        }
    }

    @Override // android.view.View
    public void setClickable(boolean z) {
        super.setClickable(z);
        d dVar = this.h;
        if (dVar != null) {
            dVar.k();
        }
    }

    public void setDragged(boolean z) {
        if (this.k != z) {
            this.k = z;
            refreshDrawableState();
            f();
            invalidate();
        }
    }

    @Override // androidx.cardview.widget.CardView
    public void setMaxCardElevation(float f) {
        super.setMaxCardElevation(f);
        this.h.m();
    }

    public void setOnCheckedChangeListener(a aVar) {
    }

    @Override // androidx.cardview.widget.CardView
    public void setPreventCornerOverlap(boolean z) {
        super.setPreventCornerOverlap(z);
        d dVar = this.h;
        dVar.m();
        dVar.l();
    }

    public void setProgress(float f) {
        d dVar = this.h;
        dVar.c.n(f);
        g gVar = dVar.d;
        if (gVar != null) {
            gVar.n(f);
        }
        g gVar2 = dVar.q;
        if (gVar2 != null) {
            gVar2.n(f);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0051  */
    @Override // androidx.cardview.widget.CardView
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setRadius(float r4) {
        /*
            r3 = this;
            super.setRadius(r4)
            com.google.android.material.card.d r0 = r3.h
            com.google.android.material.shape.j r1 = r0.m
            com.google.android.gms.internal.mlkit_vision_document_scanner.G4 r1 = r1.f()
            com.google.android.material.shape.a r2 = new com.google.android.material.shape.a
            r2.<init>(r4)
            r1.e = r2
            com.google.android.material.shape.a r2 = new com.google.android.material.shape.a
            r2.<init>(r4)
            r1.f = r2
            com.google.android.material.shape.a r2 = new com.google.android.material.shape.a
            r2.<init>(r4)
            r1.g = r2
            com.google.android.material.shape.a r2 = new com.google.android.material.shape.a
            r2.<init>(r4)
            r1.h = r2
            com.google.android.material.shape.j r4 = r1.a()
            r0.h(r4)
            android.graphics.drawable.Drawable r4 = r0.i
            r4.invalidateSelf()
            boolean r4 = r0.i()
            if (r4 != 0) goto L51
            com.google.android.material.card.b r4 = r0.a
            boolean r4 = r4.getPreventCornerOverlap()
            if (r4 == 0) goto L54
            com.google.android.material.shape.g r4 = r0.c
            com.google.android.material.shape.f r1 = r4.a
            com.google.android.material.shape.j r1 = r1.a
            android.graphics.RectF r4 = r4.g()
            boolean r4 = r1.e(r4)
            if (r4 != 0) goto L54
        L51:
            r0.l()
        L54:
            boolean r4 = r0.i()
            if (r4 == 0) goto L5d
            r0.m()
        L5d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.card.b.setRadius(float):void");
    }

    public void setRippleColor(ColorStateList colorStateList) {
        d dVar = this.h;
        dVar.k = colorStateList;
        int[] iArr = com.google.android.material.ripple.a.a;
        RippleDrawable rippleDrawable = dVar.o;
        if (rippleDrawable != null) {
            rippleDrawable.setColor(colorStateList);
        }
    }

    public void setRippleColorResource(int i) {
        ColorStateList colorStateListC = androidx.core.content.c.c(getContext(), i);
        d dVar = this.h;
        dVar.k = colorStateListC;
        int[] iArr = com.google.android.material.ripple.a.a;
        RippleDrawable rippleDrawable = dVar.o;
        if (rippleDrawable != null) {
            rippleDrawable.setColor(colorStateListC);
        }
    }

    @Override // com.google.android.material.shape.s
    public void setShapeAppearanceModel(@NonNull j jVar) {
        setClipToOutline(jVar.e(getBoundsAsRectF()));
        this.h.h(jVar);
    }

    public void setStrokeColor(int i) {
        setStrokeColor(ColorStateList.valueOf(i));
    }

    public void setStrokeWidth(int i) {
        d dVar = this.h;
        if (i != dVar.h) {
            dVar.h = i;
            g gVar = dVar.d;
            ColorStateList colorStateList = dVar.n;
            gVar.a.j = i;
            gVar.invalidateSelf();
            gVar.r(colorStateList);
        }
        invalidate();
    }

    @Override // androidx.cardview.widget.CardView
    public void setUseCompatPadding(boolean z) {
        super.setUseCompatPadding(z);
        d dVar = this.h;
        dVar.m();
        dVar.l();
    }

    @Override // android.widget.Checkable
    public final void toggle() {
        d dVar = this.h;
        if (dVar != null && dVar.s && isEnabled()) {
            this.j = !this.j;
            refreshDrawableState();
            f();
            dVar.f(this.j, true);
        }
    }

    public b(Context context, int i) {
        this(context, null, com.quizlet.quizletandroid.R.attr.materialCardViewStyle);
    }

    public void setStrokeColor(ColorStateList colorStateList) {
        d dVar = this.h;
        if (dVar.n != colorStateList) {
            dVar.n = colorStateList;
            g gVar = dVar.d;
            gVar.a.j = dVar.h;
            gVar.invalidateSelf();
            gVar.r(colorStateList);
        }
        invalidate();
    }

    public b(Context context, AttributeSet attributeSet, int i) {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, i, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CardView), attributeSet, i);
        this.j = false;
        this.k = false;
        this.i = true;
        TypedArray typedArrayL = p.l(getContext(), attributeSet, com.google.android.material.a.z, i, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_CardView, new int[0]);
        d dVar = new d(this, attributeSet, i);
        this.h = dVar;
        ColorStateList cardBackgroundColor = super.getCardBackgroundColor();
        g gVar = dVar.c;
        gVar.m(cardBackgroundColor);
        dVar.b.set(super.getContentPaddingLeft(), super.getContentPaddingTop(), super.getContentPaddingRight(), super.getContentPaddingBottom());
        dVar.l();
        b bVar = dVar.a;
        ColorStateList colorStateListA = AbstractC3442d4.a(bVar.getContext(), typedArrayL, 11);
        dVar.n = colorStateListA;
        if (colorStateListA == null) {
            dVar.n = ColorStateList.valueOf(-1);
        }
        dVar.h = typedArrayL.getDimensionPixelSize(12, 0);
        boolean z = typedArrayL.getBoolean(0, false);
        dVar.s = z;
        bVar.setLongClickable(z);
        dVar.l = AbstractC3442d4.a(bVar.getContext(), typedArrayL, 6);
        dVar.g(AbstractC3442d4.c(bVar.getContext(), typedArrayL, 2));
        dVar.f = typedArrayL.getDimensionPixelSize(5, 0);
        dVar.e = typedArrayL.getDimensionPixelSize(4, 0);
        dVar.g = typedArrayL.getInteger(3, 8388661);
        ColorStateList colorStateListA2 = AbstractC3442d4.a(bVar.getContext(), typedArrayL, 7);
        dVar.k = colorStateListA2;
        if (colorStateListA2 == null) {
            dVar.k = ColorStateList.valueOf(X3.b(com.quizlet.quizletandroid.R.attr.colorControlHighlight, bVar));
        }
        ColorStateList colorStateListA3 = AbstractC3442d4.a(bVar.getContext(), typedArrayL, 1);
        g gVar2 = dVar.d;
        gVar2.m(colorStateListA3 == null ? ColorStateList.valueOf(0) : colorStateListA3);
        int[] iArr = com.google.android.material.ripple.a.a;
        RippleDrawable rippleDrawable = dVar.o;
        if (rippleDrawable != null) {
            rippleDrawable.setColor(dVar.k);
        }
        gVar.l(bVar.getCardElevation());
        float f = dVar.h;
        ColorStateList colorStateList = dVar.n;
        gVar2.a.j = f;
        gVar2.invalidateSelf();
        gVar2.r(colorStateList);
        bVar.setBackgroundInternal(dVar.d(gVar));
        Drawable drawableC = dVar.j() ? dVar.c() : gVar2;
        dVar.i = drawableC;
        bVar.setForeground(dVar.d(drawableC));
        typedArrayL.recycle();
    }

    @Override // androidx.cardview.widget.CardView
    public void setCardBackgroundColor(int i) {
        this.h.c.m(ColorStateList.valueOf(i));
    }
}
