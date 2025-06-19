package com.google.android.material.chip;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.MotionEvent;
import android.view.PointerIcon;
import android.view.View;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.CompoundButton;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.K;
import androidx.appcompat.widget.r;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.webkit.internal.p;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.material.internal.n;
import com.google.android.material.shape.s;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class Chip extends r implements e, s, com.google.android.material.internal.i {
    public static final Rect x = new Rect();
    public static final int[] y = {R.attr.state_selected};
    public static final int[] z = {R.attr.state_checkable};
    public f e;
    public InsetDrawable f;
    public RippleDrawable g;
    public View.OnClickListener h;
    public CompoundButton.OnCheckedChangeListener i;
    public com.google.android.material.internal.h j;
    public boolean k;
    public boolean l;
    public boolean m;
    public boolean n;
    public boolean o;
    public int p;
    public int q;
    public CharSequence r;
    public final d s;
    public boolean t;
    public final Rect u;
    public final RectF v;
    public final b w;

    public Chip(Context context) {
        this(context, null);
    }

    @NonNull
    private RectF getCloseIconTouchBounds() {
        RectF rectF = this.v;
        rectF.setEmpty();
        if (c() && this.h != null) {
            f fVar = this.e;
            Rect bounds = fVar.getBounds();
            rectF.setEmpty();
            if (fVar.a0()) {
                float f = fVar.o1 + fVar.n1 + fVar.X + fVar.m1 + fVar.l1;
                if (fVar.getLayoutDirection() == 0) {
                    float f2 = bounds.right;
                    rectF.right = f2;
                    rectF.left = f2 - f;
                } else {
                    float f3 = bounds.left;
                    rectF.left = f3;
                    rectF.right = f3 + f;
                }
                rectF.top = bounds.top;
                rectF.bottom = bounds.bottom;
            }
        }
        return rectF;
    }

    /* JADX INFO: Access modifiers changed from: private */
    @NonNull
    public Rect getCloseIconTouchBoundsInt() {
        RectF closeIconTouchBounds = getCloseIconTouchBounds();
        int i = (int) closeIconTouchBounds.left;
        int i2 = (int) closeIconTouchBounds.top;
        int i3 = (int) closeIconTouchBounds.right;
        int i4 = (int) closeIconTouchBounds.bottom;
        Rect rect = this.u;
        rect.set(i, i2, i3, i4);
        return rect;
    }

    private com.google.android.material.resources.e getTextAppearance() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.v1.g;
        }
        return null;
    }

    private void setCloseIconHovered(boolean z2) {
        if (this.m != z2) {
            this.m = z2;
            refreshDrawableState();
        }
    }

    private void setCloseIconPressed(boolean z2) {
        if (this.l != z2) {
            this.l = z2;
            refreshDrawableState();
        }
    }

    public final void b(int i) {
        this.q = i;
        if (!this.o) {
            InsetDrawable insetDrawable = this.f;
            if (insetDrawable == null) {
                int[] iArr = com.google.android.material.ripple.a.a;
                e();
                return;
            } else {
                if (insetDrawable != null) {
                    this.f = null;
                    setMinWidth(0);
                    setMinHeight((int) getChipMinHeight());
                    int[] iArr2 = com.google.android.material.ripple.a.a;
                    e();
                    return;
                }
                return;
            }
        }
        int iMax = Math.max(0, i - ((int) this.e.A));
        int iMax2 = Math.max(0, i - this.e.getIntrinsicWidth());
        if (iMax2 <= 0 && iMax <= 0) {
            InsetDrawable insetDrawable2 = this.f;
            if (insetDrawable2 == null) {
                int[] iArr3 = com.google.android.material.ripple.a.a;
                e();
                return;
            } else {
                if (insetDrawable2 != null) {
                    this.f = null;
                    setMinWidth(0);
                    setMinHeight((int) getChipMinHeight());
                    int[] iArr4 = com.google.android.material.ripple.a.a;
                    e();
                    return;
                }
                return;
            }
        }
        int i2 = iMax2 > 0 ? iMax2 / 2 : 0;
        int i3 = iMax > 0 ? iMax / 2 : 0;
        if (this.f != null) {
            Rect rect = new Rect();
            this.f.getPadding(rect);
            if (rect.top == i3 && rect.bottom == i3 && rect.left == i2 && rect.right == i2) {
                int[] iArr5 = com.google.android.material.ripple.a.a;
                e();
                return;
            }
        }
        if (getMinHeight() != i) {
            setMinHeight(i);
        }
        if (getMinWidth() != i) {
            setMinWidth(i);
        }
        this.f = new InsetDrawable((Drawable) this.e, i2, i3, i2, i3);
        int[] iArr6 = com.google.android.material.ripple.a.a;
        e();
    }

    public final boolean c() {
        f fVar = this.e;
        if (fVar == null) {
            return false;
        }
        Drawable drawable = fVar.M;
        return (drawable != null ? AbstractC3179j6.e(drawable) : null) != null;
    }

    public final void d() {
        f fVar;
        if (!c() || (fVar = this.e) == null || !fVar.L || this.h == null) {
            V.o(this, null);
            this.t = false;
        } else {
            V.o(this, this.s);
            this.t = true;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x006c  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean dispatchHoverEvent(android.view.MotionEvent r10) {
        /*
            r9 = this;
            boolean r0 = r9.t
            if (r0 != 0) goto L9
            boolean r10 = super.dispatchHoverEvent(r10)
            return r10
        L9:
            com.google.android.material.chip.d r0 = r9.s
            android.view.accessibility.AccessibilityManager r1 = r0.h
            boolean r2 = r1.isEnabled()
            r3 = 1
            r4 = 0
            if (r2 == 0) goto L6c
            boolean r1 = r1.isTouchExplorationEnabled()
            if (r1 != 0) goto L1c
            goto L6c
        L1c:
            int r1 = r10.getAction()
            r2 = 256(0x100, float:3.59E-43)
            r5 = 7
            r6 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r1 == r5) goto L3d
            r5 = 9
            if (r1 == r5) goto L3d
            r5 = 10
            if (r1 == r5) goto L30
            goto L6c
        L30:
            int r1 = r0.m
            if (r1 == r6) goto L6c
            if (r1 != r6) goto L37
            goto L72
        L37:
            r0.m = r6
            r0.q(r1, r2)
            return r3
        L3d:
            float r1 = r10.getX()
            float r5 = r10.getY()
            com.google.android.material.chip.Chip r7 = r0.q
            boolean r8 = r7.c()
            if (r8 == 0) goto L59
            android.graphics.RectF r7 = r7.getCloseIconTouchBounds()
            boolean r1 = r7.contains(r1, r5)
            if (r1 == 0) goto L59
            r1 = r3
            goto L5a
        L59:
            r1 = r4
        L5a:
            int r5 = r0.m
            if (r5 != r1) goto L5f
            goto L69
        L5f:
            r0.m = r1
            r7 = 128(0x80, float:1.8E-43)
            r0.q(r1, r7)
            r0.q(r5, r2)
        L69:
            if (r1 == r6) goto L6c
            goto L72
        L6c:
            boolean r10 = super.dispatchHoverEvent(r10)
            if (r10 == 0) goto L73
        L72:
            return r3
        L73:
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.chip.Chip.dispatchHoverEvent(android.view.MotionEvent):boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:31:0x0058  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean dispatchKeyEvent(android.view.KeyEvent r10) {
        /*
            r9 = this;
            boolean r0 = r9.t
            if (r0 != 0) goto L9
            boolean r10 = super.dispatchKeyEvent(r10)
            return r10
        L9:
            com.google.android.material.chip.d r0 = r9.s
            r0.getClass()
            int r1 = r10.getAction()
            r2 = 0
            r3 = 1
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r1 == r3) goto L9d
            int r1 = r10.getKeyCode()
            r5 = 61
            r6 = 0
            if (r1 == r5) goto L87
            r5 = 66
            if (r1 == r5) goto L58
            switch(r1) {
                case 19: goto L2a;
                case 20: goto L2a;
                case 21: goto L2a;
                case 22: goto L2a;
                case 23: goto L58;
                default: goto L28;
            }
        L28:
            goto L9d
        L2a:
            boolean r7 = r10.hasNoModifiers()
            if (r7 == 0) goto L9d
            r7 = 19
            if (r1 == r7) goto L42
            r7 = 21
            if (r1 == r7) goto L3f
            r7 = 22
            if (r1 == r7) goto L44
            r5 = 130(0x82, float:1.82E-43)
            goto L44
        L3f:
            r5 = 17
            goto L44
        L42:
            r5 = 33
        L44:
            int r1 = r10.getRepeatCount()
            int r1 = r1 + r3
            r7 = r2
        L4a:
            if (r2 >= r1) goto L56
            boolean r8 = r0.m(r5, r6)
            if (r8 == 0) goto L56
            int r2 = r2 + 1
            r7 = r3
            goto L4a
        L56:
            r2 = r7
            goto L9d
        L58:
            boolean r1 = r10.hasNoModifiers()
            if (r1 == 0) goto L9d
            int r1 = r10.getRepeatCount()
            if (r1 != 0) goto L9d
            int r1 = r0.l
            if (r1 == r4) goto L85
            com.google.android.material.chip.Chip r5 = r0.q
            if (r1 != 0) goto L70
            r5.performClick()
            goto L85
        L70:
            if (r1 != r3) goto L85
            r5.playSoundEffect(r2)
            android.view.View$OnClickListener r1 = r5.h
            if (r1 == 0) goto L7c
            r1.onClick(r5)
        L7c:
            boolean r1 = r5.t
            if (r1 == 0) goto L85
            com.google.android.material.chip.d r1 = r5.s
            r1.q(r3, r3)
        L85:
            r2 = r3
            goto L9d
        L87:
            boolean r1 = r10.hasNoModifiers()
            if (r1 == 0) goto L93
            r1 = 2
            boolean r2 = r0.m(r1, r6)
            goto L9d
        L93:
            boolean r1 = r10.hasModifiers(r3)
            if (r1 == 0) goto L9d
            boolean r2 = r0.m(r3, r6)
        L9d:
            if (r2 == 0) goto La4
            int r0 = r0.l
            if (r0 == r4) goto La4
            return r3
        La4:
            boolean r10 = super.dispatchKeyEvent(r10)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.chip.Chip.dispatchKeyEvent(android.view.KeyEvent):boolean");
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [boolean, int] */
    @Override // androidx.appcompat.widget.r, android.widget.CompoundButton, android.widget.TextView, android.view.View
    public final void drawableStateChanged() {
        int i;
        super.drawableStateChanged();
        f fVar = this.e;
        boolean zD = false;
        if (fVar != null && f.B(fVar.M)) {
            f fVar2 = this.e;
            ?? IsEnabled = isEnabled();
            int i2 = IsEnabled;
            if (this.n) {
                i2 = IsEnabled + 1;
            }
            int i3 = i2;
            if (this.m) {
                i3 = i2 + 1;
            }
            int i4 = i3;
            if (this.l) {
                i4 = i3 + 1;
            }
            int i5 = i4;
            if (isChecked()) {
                i5 = i4 + 1;
            }
            int[] iArr = new int[i5];
            if (isEnabled()) {
                iArr[0] = 16842910;
                i = 1;
            } else {
                i = 0;
            }
            if (this.n) {
                iArr[i] = 16842908;
                i++;
            }
            if (this.m) {
                iArr[i] = 16843623;
                i++;
            }
            if (this.l) {
                iArr[i] = 16842919;
                i++;
            }
            if (isChecked()) {
                iArr[i] = 16842913;
            }
            if (!Arrays.equals(fVar2.J1, iArr)) {
                fVar2.J1 = iArr;
                if (fVar2.a0()) {
                    zD = fVar2.D(fVar2.getState(), iArr);
                }
            }
        }
        if (zD) {
            invalidate();
        }
    }

    public final void e() {
        this.g = new RippleDrawable(com.google.android.material.ripple.a.b(this.e.E), getBackgroundDrawable(), null);
        this.e.getClass();
        RippleDrawable rippleDrawable = this.g;
        WeakHashMap weakHashMap = V.a;
        setBackground(rippleDrawable);
        f();
    }

    public final void f() {
        f fVar;
        if (TextUtils.isEmpty(getText()) || (fVar = this.e) == null) {
            return;
        }
        int iY = (int) (fVar.y() + fVar.o1 + fVar.l1);
        f fVar2 = this.e;
        int iX = (int) (fVar2.x() + fVar2.h1 + fVar2.k1);
        if (this.f != null) {
            Rect rect = new Rect();
            this.f.getPadding(rect);
            iX += rect.left;
            iY += rect.right;
        }
        int paddingTop = getPaddingTop();
        int paddingBottom = getPaddingBottom();
        WeakHashMap weakHashMap = V.a;
        setPaddingRelative(iX, paddingTop, iY, paddingBottom);
    }

    public final void g() {
        TextPaint paint = getPaint();
        f fVar = this.e;
        if (fVar != null) {
            paint.drawableState = fVar.getState();
        }
        com.google.android.material.resources.e textAppearance = getTextAppearance();
        if (textAppearance != null) {
            textAppearance.e(getContext(), paint, this.w);
        }
    }

    @Override // android.widget.CheckBox, android.widget.CompoundButton, android.widget.Button, android.widget.TextView, android.view.View
    @NonNull
    public CharSequence getAccessibilityClassName() {
        if (!TextUtils.isEmpty(this.r)) {
            return this.r;
        }
        f fVar = this.e;
        if (!(fVar != null && fVar.Z)) {
            return isClickable() ? "android.widget.Button" : "android.view.View";
        }
        ViewParent parent = getParent();
        return ((parent instanceof j) && ((j) parent).h.a) ? "android.widget.RadioButton" : "android.widget.Button";
    }

    public Drawable getBackgroundDrawable() {
        InsetDrawable insetDrawable = this.f;
        return insetDrawable == null ? this.e : insetDrawable;
    }

    public Drawable getCheckedIcon() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.d1;
        }
        return null;
    }

    public ColorStateList getCheckedIconTint() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.e1;
        }
        return null;
    }

    public ColorStateList getChipBackgroundColor() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.z;
        }
        return null;
    }

    public float getChipCornerRadius() {
        f fVar = this.e;
        return fVar != null ? Math.max(DefinitionKt.NO_Float_VALUE, fVar.z()) : DefinitionKt.NO_Float_VALUE;
    }

    public Drawable getChipDrawable() {
        return this.e;
    }

    public float getChipEndPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.o1 : DefinitionKt.NO_Float_VALUE;
    }

    public Drawable getChipIcon() {
        Drawable drawable;
        f fVar = this.e;
        if (fVar == null || (drawable = fVar.H) == null) {
            return null;
        }
        return AbstractC3179j6.e(drawable);
    }

    public float getChipIconSize() {
        f fVar = this.e;
        return fVar != null ? fVar.J : DefinitionKt.NO_Float_VALUE;
    }

    public ColorStateList getChipIconTint() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.I;
        }
        return null;
    }

    public float getChipMinHeight() {
        f fVar = this.e;
        return fVar != null ? fVar.A : DefinitionKt.NO_Float_VALUE;
    }

    public float getChipStartPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.h1 : DefinitionKt.NO_Float_VALUE;
    }

    public ColorStateList getChipStrokeColor() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.C;
        }
        return null;
    }

    public float getChipStrokeWidth() {
        f fVar = this.e;
        return fVar != null ? fVar.D : DefinitionKt.NO_Float_VALUE;
    }

    @Deprecated
    public CharSequence getChipText() {
        return getText();
    }

    public Drawable getCloseIcon() {
        Drawable drawable;
        f fVar = this.e;
        if (fVar == null || (drawable = fVar.M) == null) {
            return null;
        }
        return AbstractC3179j6.e(drawable);
    }

    public CharSequence getCloseIconContentDescription() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.Y;
        }
        return null;
    }

    public float getCloseIconEndPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.n1 : DefinitionKt.NO_Float_VALUE;
    }

    public float getCloseIconSize() {
        f fVar = this.e;
        return fVar != null ? fVar.X : DefinitionKt.NO_Float_VALUE;
    }

    public float getCloseIconStartPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.m1 : DefinitionKt.NO_Float_VALUE;
    }

    public ColorStateList getCloseIconTint() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.W;
        }
        return null;
    }

    @Override // android.widget.TextView
    public TextUtils.TruncateAt getEllipsize() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.M1;
        }
        return null;
    }

    @Override // android.widget.TextView, android.view.View
    public final void getFocusedRect(Rect rect) {
        if (this.t) {
            d dVar = this.s;
            if (dVar.l == 1 || dVar.k == 1) {
                rect.set(getCloseIconTouchBoundsInt());
                return;
            }
        }
        super.getFocusedRect(rect);
    }

    public com.google.android.material.animation.f getHideMotionSpec() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.g1;
        }
        return null;
    }

    public float getIconEndPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.j1 : DefinitionKt.NO_Float_VALUE;
    }

    public float getIconStartPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.i1 : DefinitionKt.NO_Float_VALUE;
    }

    public ColorStateList getRippleColor() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.E;
        }
        return null;
    }

    @NonNull
    public com.google.android.material.shape.j getShapeAppearanceModel() {
        return this.e.a.a;
    }

    public com.google.android.material.animation.f getShowMotionSpec() {
        f fVar = this.e;
        if (fVar != null) {
            return fVar.f1;
        }
        return null;
    }

    public float getTextEndPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.l1 : DefinitionKt.NO_Float_VALUE;
    }

    public float getTextStartPadding() {
        f fVar = this.e;
        return fVar != null ? fVar.k1 : DefinitionKt.NO_Float_VALUE;
    }

    @Override // android.widget.TextView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        AbstractC3466h4.b(this, this.e);
    }

    @Override // android.widget.CompoundButton, android.widget.TextView, android.view.View
    public final int[] onCreateDrawableState(int i) {
        int[] iArrOnCreateDrawableState = super.onCreateDrawableState(i + 2);
        if (isChecked()) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, y);
        }
        f fVar = this.e;
        if (fVar != null && fVar.Z) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, z);
        }
        return iArrOnCreateDrawableState;
    }

    @Override // android.widget.TextView, android.view.View
    public final void onFocusChanged(boolean z2, int i, Rect rect) {
        super.onFocusChanged(z2, i, rect);
        if (this.t) {
            d dVar = this.s;
            int i2 = dVar.l;
            if (i2 != Integer.MIN_VALUE) {
                dVar.j(i2);
            }
            if (z2) {
                dVar.m(i, rect);
            }
        }
    }

    @Override // android.view.View
    public final boolean onHoverEvent(MotionEvent motionEvent) {
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 7) {
            setCloseIconHovered(getCloseIconTouchBounds().contains(motionEvent.getX(), motionEvent.getY()));
        } else if (actionMasked == 10) {
            setCloseIconHovered(false);
        }
        return super.onHoverEvent(motionEvent);
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        int i;
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName(getAccessibilityClassName());
        f fVar = this.e;
        accessibilityNodeInfo.setCheckable(fVar != null && fVar.Z);
        accessibilityNodeInfo.setClickable(isClickable());
        if (getParent() instanceof j) {
            j jVar = (j) getParent();
            if (jVar.c) {
                i = 0;
                for (int i2 = 0; i2 < jVar.getChildCount(); i2++) {
                    View childAt = jVar.getChildAt(i2);
                    if ((childAt instanceof Chip) && jVar.getChildAt(i2).getVisibility() == 0) {
                        if (((Chip) childAt) == this) {
                            break;
                        } else {
                            i++;
                        }
                    }
                }
                i = -1;
            } else {
                i = -1;
            }
            Object tag = getTag(com.quizlet.quizletandroid.R.id.row_index_key);
            accessibilityNodeInfo.setCollectionItemInfo((AccessibilityNodeInfo.CollectionItemInfo) p.r(tag instanceof Integer ? ((Integer) tag).intValue() : -1, 1, i, 1, isChecked()).b);
        }
    }

    @Override // android.widget.Button, android.widget.TextView, android.view.View
    public final PointerIcon onResolvePointerIcon(MotionEvent motionEvent, int i) {
        return (getCloseIconTouchBounds().contains(motionEvent.getX(), motionEvent.getY()) && isEnabled()) ? PointerIcon.getSystemIcon(getContext(), 1002) : super.onResolvePointerIcon(motionEvent, i);
    }

    @Override // android.widget.TextView, android.view.View
    public final void onRtlPropertiesChanged(int i) {
        super.onRtlPropertiesChanged(i);
        if (this.p != i) {
            this.p = i;
            f();
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x001e, code lost:
    
        if (r0 != 3) goto L28;
     */
    @Override // android.widget.TextView, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean onTouchEvent(android.view.MotionEvent r6) {
        /*
            r5 = this;
            int r0 = r6.getActionMasked()
            android.graphics.RectF r1 = r5.getCloseIconTouchBounds()
            float r2 = r6.getX()
            float r3 = r6.getY()
            boolean r1 = r1.contains(r2, r3)
            r2 = 0
            r3 = 1
            if (r0 == 0) goto L4a
            if (r0 == r3) goto L2c
            r4 = 2
            if (r0 == r4) goto L21
            r1 = 3
            if (r0 == r1) goto L45
            goto L50
        L21:
            boolean r0 = r5.l
            if (r0 == 0) goto L50
            if (r1 != 0) goto L2a
            r5.setCloseIconPressed(r2)
        L2a:
            r0 = r3
            goto L51
        L2c:
            boolean r0 = r5.l
            if (r0 == 0) goto L45
            r5.playSoundEffect(r2)
            android.view.View$OnClickListener r0 = r5.h
            if (r0 == 0) goto L3a
            r0.onClick(r5)
        L3a:
            boolean r0 = r5.t
            if (r0 == 0) goto L43
            com.google.android.material.chip.d r0 = r5.s
            r0.q(r3, r3)
        L43:
            r0 = r3
            goto L46
        L45:
            r0 = r2
        L46:
            r5.setCloseIconPressed(r2)
            goto L51
        L4a:
            if (r1 == 0) goto L50
            r5.setCloseIconPressed(r3)
            goto L2a
        L50:
            r0 = r2
        L51:
            if (r0 != 0) goto L5b
            boolean r6 = super.onTouchEvent(r6)
            if (r6 == 0) goto L5a
            goto L5b
        L5a:
            return r2
        L5b:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.chip.Chip.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public void setAccessibilityClassName(CharSequence charSequence) {
        this.r = charSequence;
    }

    @Override // android.view.View
    public void setBackground(Drawable drawable) {
        if (drawable == getBackgroundDrawable() || drawable == this.g) {
            super.setBackground(drawable);
        } else {
            Log.w("Chip", "Do not set the background; Chip manages its own background drawable.");
        }
    }

    @Override // android.view.View
    public void setBackgroundColor(int i) {
        Log.w("Chip", "Do not set the background color; Chip manages its own background drawable.");
    }

    @Override // androidx.appcompat.widget.r, android.view.View
    public void setBackgroundDrawable(Drawable drawable) {
        if (drawable == getBackgroundDrawable() || drawable == this.g) {
            super.setBackgroundDrawable(drawable);
        } else {
            Log.w("Chip", "Do not set the background drawable; Chip manages its own background drawable.");
        }
    }

    @Override // androidx.appcompat.widget.r, android.view.View
    public void setBackgroundResource(int i) {
        Log.w("Chip", "Do not set the background resource; Chip manages its own background drawable.");
    }

    @Override // android.view.View
    public void setBackgroundTintList(ColorStateList colorStateList) {
        Log.w("Chip", "Do not set the background tint list; Chip manages its own background drawable.");
    }

    @Override // android.view.View
    public void setBackgroundTintMode(PorterDuff.Mode mode) {
        Log.w("Chip", "Do not set the background tint mode; Chip manages its own background drawable.");
    }

    public void setCheckable(boolean z2) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.E(z2);
        }
    }

    public void setCheckableResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.E(fVar.p1.getResources().getBoolean(i));
        }
    }

    @Override // android.widget.CompoundButton, android.widget.Checkable
    public void setChecked(boolean z2) {
        f fVar = this.e;
        if (fVar == null) {
            this.k = z2;
        } else if (fVar.Z) {
            super.setChecked(z2);
        }
    }

    public void setCheckedIcon(Drawable drawable) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.F(drawable);
        }
    }

    @Deprecated
    public void setCheckedIconEnabled(boolean z2) {
        setCheckedIconVisible(z2);
    }

    @Deprecated
    public void setCheckedIconEnabledResource(int i) {
        setCheckedIconVisible(i);
    }

    public void setCheckedIconResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.F(com.facebook.appevents.g.f(fVar.p1, i));
        }
    }

    public void setCheckedIconTint(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.G(colorStateList);
        }
    }

    public void setCheckedIconTintResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.G(androidx.core.content.c.c(fVar.p1, i));
        }
    }

    public void setCheckedIconVisible(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.H(fVar.p1.getResources().getBoolean(i));
        }
    }

    public void setChipBackgroundColor(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar == null || fVar.z == colorStateList) {
            return;
        }
        fVar.z = colorStateList;
        fVar.onStateChange(fVar.getState());
    }

    public void setChipBackgroundColorResource(int i) {
        ColorStateList colorStateListC;
        f fVar = this.e;
        if (fVar == null || fVar.z == (colorStateListC = androidx.core.content.c.c(fVar.p1, i))) {
            return;
        }
        fVar.z = colorStateListC;
        fVar.onStateChange(fVar.getState());
    }

    @Deprecated
    public void setChipCornerRadius(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.I(f);
        }
    }

    @Deprecated
    public void setChipCornerRadiusResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.I(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setChipDrawable(@NonNull f fVar) {
        f fVar2 = this.e;
        if (fVar2 != fVar) {
            if (fVar2 != null) {
                fVar2.L1 = new WeakReference(null);
            }
            this.e = fVar;
            fVar.N1 = false;
            fVar.L1 = new WeakReference(this);
            b(this.q);
        }
    }

    public void setChipEndPadding(float f) {
        f fVar = this.e;
        if (fVar == null || fVar.o1 == f) {
            return;
        }
        fVar.o1 = f;
        fVar.invalidateSelf();
        fVar.C();
    }

    public void setChipEndPaddingResource(int i) throws Resources.NotFoundException {
        f fVar = this.e;
        if (fVar != null) {
            float dimension = fVar.p1.getResources().getDimension(i);
            if (fVar.o1 != dimension) {
                fVar.o1 = dimension;
                fVar.invalidateSelf();
                fVar.C();
            }
        }
    }

    public void setChipIcon(Drawable drawable) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.J(drawable);
        }
    }

    @Deprecated
    public void setChipIconEnabled(boolean z2) {
        setChipIconVisible(z2);
    }

    @Deprecated
    public void setChipIconEnabledResource(int i) {
        setChipIconVisible(i);
    }

    public void setChipIconResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.J(com.facebook.appevents.g.f(fVar.p1, i));
        }
    }

    public void setChipIconSize(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.K(f);
        }
    }

    public void setChipIconSizeResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.K(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setChipIconTint(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.L(colorStateList);
        }
    }

    public void setChipIconTintResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.L(androidx.core.content.c.c(fVar.p1, i));
        }
    }

    public void setChipIconVisible(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.M(fVar.p1.getResources().getBoolean(i));
        }
    }

    public void setChipMinHeight(float f) {
        f fVar = this.e;
        if (fVar == null || fVar.A == f) {
            return;
        }
        fVar.A = f;
        fVar.invalidateSelf();
        fVar.C();
    }

    public void setChipMinHeightResource(int i) throws Resources.NotFoundException {
        f fVar = this.e;
        if (fVar != null) {
            float dimension = fVar.p1.getResources().getDimension(i);
            if (fVar.A != dimension) {
                fVar.A = dimension;
                fVar.invalidateSelf();
                fVar.C();
            }
        }
    }

    public void setChipStartPadding(float f) {
        f fVar = this.e;
        if (fVar == null || fVar.h1 == f) {
            return;
        }
        fVar.h1 = f;
        fVar.invalidateSelf();
        fVar.C();
    }

    public void setChipStartPaddingResource(int i) throws Resources.NotFoundException {
        f fVar = this.e;
        if (fVar != null) {
            float dimension = fVar.p1.getResources().getDimension(i);
            if (fVar.h1 != dimension) {
                fVar.h1 = dimension;
                fVar.invalidateSelf();
                fVar.C();
            }
        }
    }

    public void setChipStrokeColor(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.N(colorStateList);
        }
    }

    public void setChipStrokeColorResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.N(androidx.core.content.c.c(fVar.p1, i));
        }
    }

    public void setChipStrokeWidth(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.O(f);
        }
    }

    public void setChipStrokeWidthResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.O(fVar.p1.getResources().getDimension(i));
        }
    }

    @Deprecated
    public void setChipText(CharSequence charSequence) {
        setText(charSequence);
    }

    @Deprecated
    public void setChipTextResource(int i) {
        setText(getResources().getString(i));
    }

    public void setCloseIcon(Drawable drawable) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.P(drawable);
        }
        d();
    }

    public void setCloseIconContentDescription(CharSequence charSequence) {
        f fVar = this.e;
        if (fVar == null || fVar.Y == charSequence) {
            return;
        }
        androidx.core.text.b bVarC = androidx.core.text.b.c();
        bVarC.getClass();
        K k = androidx.core.text.f.a;
        fVar.Y = bVarC.d(charSequence);
        fVar.invalidateSelf();
    }

    @Deprecated
    public void setCloseIconEnabled(boolean z2) {
        setCloseIconVisible(z2);
    }

    @Deprecated
    public void setCloseIconEnabledResource(int i) {
        setCloseIconVisible(i);
    }

    public void setCloseIconEndPadding(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.Q(f);
        }
    }

    public void setCloseIconEndPaddingResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.Q(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setCloseIconResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.P(com.facebook.appevents.g.f(fVar.p1, i));
        }
        d();
    }

    public void setCloseIconSize(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.R(f);
        }
    }

    public void setCloseIconSizeResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.R(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setCloseIconStartPadding(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.S(f);
        }
    }

    public void setCloseIconStartPaddingResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.S(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setCloseIconTint(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.T(colorStateList);
        }
    }

    public void setCloseIconTintResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.T(androidx.core.content.c.c(fVar.p1, i));
        }
    }

    public void setCloseIconVisible(int i) {
        setCloseIconVisible(getResources().getBoolean(i));
    }

    @Override // androidx.appcompat.widget.r, android.widget.TextView
    public final void setCompoundDrawables(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        if (drawable != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        }
        if (drawable3 != null) {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
        super.setCompoundDrawables(drawable, drawable2, drawable3, drawable4);
    }

    @Override // androidx.appcompat.widget.r, android.widget.TextView
    public final void setCompoundDrawablesRelative(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        if (drawable != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        }
        if (drawable3 != null) {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
        super.setCompoundDrawablesRelative(drawable, drawable2, drawable3, drawable4);
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelativeWithIntrinsicBounds(int i, int i2, int i3, int i4) {
        if (i != 0) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        }
        if (i3 != 0) {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
        super.setCompoundDrawablesRelativeWithIntrinsicBounds(i, i2, i3, i4);
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesWithIntrinsicBounds(int i, int i2, int i3, int i4) {
        if (i != 0) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        }
        if (i3 != 0) {
            throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
        }
        super.setCompoundDrawablesWithIntrinsicBounds(i, i2, i3, i4);
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        f fVar = this.e;
        if (fVar != null) {
            fVar.l(f);
        }
    }

    @Override // android.widget.TextView
    public void setEllipsize(TextUtils.TruncateAt truncateAt) {
        if (this.e == null) {
            return;
        }
        if (truncateAt == TextUtils.TruncateAt.MARQUEE) {
            throw new UnsupportedOperationException("Text within a chip are not allowed to scroll.");
        }
        super.setEllipsize(truncateAt);
        f fVar = this.e;
        if (fVar != null) {
            fVar.M1 = truncateAt;
        }
    }

    public void setEnsureMinTouchTargetSize(boolean z2) {
        this.o = z2;
        b(this.q);
    }

    @Override // android.widget.TextView
    public void setGravity(int i) {
        if (i != 8388627) {
            Log.w("Chip", "Chip text must be vertically center and start aligned");
        } else {
            super.setGravity(i);
        }
    }

    public void setHideMotionSpec(com.google.android.material.animation.f fVar) {
        f fVar2 = this.e;
        if (fVar2 != null) {
            fVar2.g1 = fVar;
        }
    }

    public void setHideMotionSpecResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.g1 = com.google.android.material.animation.f.b(fVar.p1, i);
        }
    }

    public void setIconEndPadding(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.V(f);
        }
    }

    public void setIconEndPaddingResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.V(fVar.p1.getResources().getDimension(i));
        }
    }

    public void setIconStartPadding(float f) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.W(f);
        }
    }

    public void setIconStartPaddingResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.W(fVar.p1.getResources().getDimension(i));
        }
    }

    @Override // com.google.android.material.internal.i
    public void setInternalOnCheckedChangeListener(com.google.android.material.internal.h hVar) {
        this.j = hVar;
    }

    @Override // android.view.View
    public void setLayoutDirection(int i) {
        if (this.e == null) {
            return;
        }
        super.setLayoutDirection(i);
    }

    @Override // android.widget.TextView
    public void setLines(int i) {
        if (i > 1) {
            throw new UnsupportedOperationException("Chip does not support multi-line text");
        }
        super.setLines(i);
    }

    @Override // android.widget.TextView
    public void setMaxLines(int i) {
        if (i > 1) {
            throw new UnsupportedOperationException("Chip does not support multi-line text");
        }
        super.setMaxLines(i);
    }

    @Override // android.widget.TextView
    public void setMaxWidth(int i) {
        super.setMaxWidth(i);
        f fVar = this.e;
        if (fVar != null) {
            fVar.O1 = i;
        }
    }

    @Override // android.widget.TextView
    public void setMinLines(int i) {
        if (i > 1) {
            throw new UnsupportedOperationException("Chip does not support multi-line text");
        }
        super.setMinLines(i);
    }

    @Override // android.widget.CompoundButton
    public void setOnCheckedChangeListener(CompoundButton.OnCheckedChangeListener onCheckedChangeListener) {
        this.i = onCheckedChangeListener;
    }

    public void setOnCloseIconClickListener(View.OnClickListener onClickListener) {
        this.h = onClickListener;
        d();
    }

    public void setRippleColor(ColorStateList colorStateList) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.X(colorStateList);
        }
        this.e.getClass();
        e();
    }

    public void setRippleColorResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.X(androidx.core.content.c.c(fVar.p1, i));
            this.e.getClass();
            e();
        }
    }

    @Override // com.google.android.material.shape.s
    public void setShapeAppearanceModel(@NonNull com.google.android.material.shape.j jVar) {
        this.e.setShapeAppearanceModel(jVar);
    }

    public void setShowMotionSpec(com.google.android.material.animation.f fVar) {
        f fVar2 = this.e;
        if (fVar2 != null) {
            fVar2.f1 = fVar;
        }
    }

    public void setShowMotionSpecResource(int i) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.f1 = com.google.android.material.animation.f.b(fVar.p1, i);
        }
    }

    @Override // android.widget.TextView
    public void setSingleLine(boolean z2) {
        if (!z2) {
            throw new UnsupportedOperationException("Chip does not support multi-line text");
        }
        super.setSingleLine(z2);
    }

    @Override // android.widget.TextView
    public final void setText(CharSequence charSequence, TextView.BufferType bufferType) {
        f fVar = this.e;
        if (fVar == null) {
            return;
        }
        if (charSequence == null) {
            charSequence = "";
        }
        super.setText(fVar.N1 ? null : charSequence, bufferType);
        f fVar2 = this.e;
        if (fVar2 == null || TextUtils.equals(fVar2.F, charSequence)) {
            return;
        }
        fVar2.F = charSequence;
        fVar2.v1.e = true;
        fVar2.invalidateSelf();
        fVar2.C();
    }

    public void setTextAppearance(com.google.android.material.resources.e eVar) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.v1.b(eVar, fVar.p1);
        }
        g();
    }

    public void setTextAppearanceResource(int i) {
        setTextAppearance(getContext(), i);
    }

    public void setTextEndPadding(float f) {
        f fVar = this.e;
        if (fVar == null || fVar.l1 == f) {
            return;
        }
        fVar.l1 = f;
        fVar.invalidateSelf();
        fVar.C();
    }

    public void setTextEndPaddingResource(int i) throws Resources.NotFoundException {
        f fVar = this.e;
        if (fVar != null) {
            float dimension = fVar.p1.getResources().getDimension(i);
            if (fVar.l1 != dimension) {
                fVar.l1 = dimension;
                fVar.invalidateSelf();
                fVar.C();
            }
        }
    }

    @Override // android.widget.TextView
    public final void setTextSize(int i, float f) {
        super.setTextSize(i, f);
        f fVar = this.e;
        if (fVar != null) {
            float fApplyDimension = TypedValue.applyDimension(i, f, getResources().getDisplayMetrics());
            n nVar = fVar.v1;
            com.google.android.material.resources.e eVar = nVar.g;
            if (eVar != null) {
                eVar.k = fApplyDimension;
                nVar.a.setTextSize(fApplyDimension);
                fVar.a();
            }
        }
        g();
    }

    public void setTextStartPadding(float f) {
        f fVar = this.e;
        if (fVar == null || fVar.k1 == f) {
            return;
        }
        fVar.k1 = f;
        fVar.invalidateSelf();
        fVar.C();
    }

    public void setTextStartPaddingResource(int i) throws Resources.NotFoundException {
        f fVar = this.e;
        if (fVar != null) {
            float dimension = fVar.p1.getResources().getDimension(i);
            if (fVar.k1 != dimension) {
                fVar.k1 = dimension;
                fVar.invalidateSelf();
                fVar.C();
            }
        }
    }

    public Chip(Context context, AttributeSet attributeSet) {
        int resourceId;
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action), attributeSet, com.quizlet.quizletandroid.R.attr.chipStyle);
        this.u = new Rect();
        this.v = new RectF();
        this.w = new b(this, 0);
        Context context2 = getContext();
        if (attributeSet != null) {
            if (attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "background") != null) {
                Log.w("Chip", "Do not set the background; Chip manages its own background drawable.");
            }
            if (attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "drawableLeft") != null) {
                throw new UnsupportedOperationException("Please set left drawable using R.attr#chipIcon.");
            }
            if (attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "drawableStart") != null) {
                throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
            }
            if (attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "drawableEnd") != null) {
                throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
            }
            if (attributeSet.getAttributeValue("http://schemas.android.com/apk/res/android", "drawableRight") != null) {
                throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
            }
            if (!attributeSet.getAttributeBooleanValue("http://schemas.android.com/apk/res/android", "singleLine", true) || attributeSet.getAttributeIntValue("http://schemas.android.com/apk/res/android", "lines", 1) != 1 || attributeSet.getAttributeIntValue("http://schemas.android.com/apk/res/android", "minLines", 1) != 1 || attributeSet.getAttributeIntValue("http://schemas.android.com/apk/res/android", "maxLines", 1) != 1) {
                throw new UnsupportedOperationException("Chip does not support multi-line text");
            }
            if (attributeSet.getAttributeIntValue("http://schemas.android.com/apk/res/android", "gravity", 8388627) != 8388627) {
                Log.w("Chip", "Chip text must be vertically center and start aligned");
            }
        }
        f fVar = new f(context2, attributeSet);
        int[] iArr = com.google.android.material.a.h;
        TypedArray typedArrayL = com.google.android.material.internal.p.l(fVar.p1, attributeSet, iArr, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action, new int[0]);
        fVar.P1 = typedArrayL.hasValue(37);
        Context context3 = fVar.p1;
        ColorStateList colorStateListA = AbstractC3442d4.a(context3, typedArrayL, 24);
        if (fVar.y != colorStateListA) {
            fVar.y = colorStateListA;
            fVar.onStateChange(fVar.getState());
        }
        ColorStateList colorStateListA2 = AbstractC3442d4.a(context3, typedArrayL, 11);
        if (fVar.z != colorStateListA2) {
            fVar.z = colorStateListA2;
            fVar.onStateChange(fVar.getState());
        }
        float dimension = typedArrayL.getDimension(19, DefinitionKt.NO_Float_VALUE);
        if (fVar.A != dimension) {
            fVar.A = dimension;
            fVar.invalidateSelf();
            fVar.C();
        }
        if (typedArrayL.hasValue(12)) {
            fVar.I(typedArrayL.getDimension(12, DefinitionKt.NO_Float_VALUE));
        }
        fVar.N(AbstractC3442d4.a(context3, typedArrayL, 22));
        fVar.O(typedArrayL.getDimension(23, DefinitionKt.NO_Float_VALUE));
        fVar.X(AbstractC3442d4.a(context3, typedArrayL, 36));
        String text = typedArrayL.getText(5);
        text = text == null ? "" : text;
        boolean zEquals = TextUtils.equals(fVar.F, text);
        n nVar = fVar.v1;
        if (!zEquals) {
            fVar.F = text;
            nVar.e = true;
            fVar.invalidateSelf();
            fVar.C();
        }
        com.google.android.material.resources.e eVar = (!typedArrayL.hasValue(0) || (resourceId = typedArrayL.getResourceId(0, 0)) == 0) ? null : new com.google.android.material.resources.e(context3, resourceId);
        eVar.k = typedArrayL.getDimension(1, eVar.k);
        nVar.b(eVar, context3);
        int i = typedArrayL.getInt(3, 0);
        if (i == 1) {
            fVar.M1 = TextUtils.TruncateAt.START;
        } else if (i == 2) {
            fVar.M1 = TextUtils.TruncateAt.MIDDLE;
        } else if (i == 3) {
            fVar.M1 = TextUtils.TruncateAt.END;
        }
        fVar.M(typedArrayL.getBoolean(18, false));
        if (attributeSet != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "chipIconEnabled") != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "chipIconVisible") == null) {
            fVar.M(typedArrayL.getBoolean(15, false));
        }
        fVar.J(AbstractC3442d4.c(context3, typedArrayL, 14));
        if (typedArrayL.hasValue(17)) {
            fVar.L(AbstractC3442d4.a(context3, typedArrayL, 17));
        }
        fVar.K(typedArrayL.getDimension(16, -1.0f));
        fVar.U(typedArrayL.getBoolean(31, false));
        if (attributeSet != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "closeIconEnabled") != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "closeIconVisible") == null) {
            fVar.U(typedArrayL.getBoolean(26, false));
        }
        fVar.P(AbstractC3442d4.c(context3, typedArrayL, 25));
        fVar.T(AbstractC3442d4.a(context3, typedArrayL, 30));
        fVar.R(typedArrayL.getDimension(28, DefinitionKt.NO_Float_VALUE));
        fVar.E(typedArrayL.getBoolean(6, false));
        fVar.H(typedArrayL.getBoolean(10, false));
        if (attributeSet != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "checkedIconEnabled") != null && attributeSet.getAttributeValue("http://schemas.android.com/apk/res-auto", "checkedIconVisible") == null) {
            fVar.H(typedArrayL.getBoolean(8, false));
        }
        fVar.F(AbstractC3442d4.c(context3, typedArrayL, 7));
        if (typedArrayL.hasValue(9)) {
            fVar.G(AbstractC3442d4.a(context3, typedArrayL, 9));
        }
        fVar.f1 = com.google.android.material.animation.f.a(context3, typedArrayL, 39);
        fVar.g1 = com.google.android.material.animation.f.a(context3, typedArrayL, 33);
        float dimension2 = typedArrayL.getDimension(21, DefinitionKt.NO_Float_VALUE);
        if (fVar.h1 != dimension2) {
            fVar.h1 = dimension2;
            fVar.invalidateSelf();
            fVar.C();
        }
        fVar.W(typedArrayL.getDimension(35, DefinitionKt.NO_Float_VALUE));
        fVar.V(typedArrayL.getDimension(34, DefinitionKt.NO_Float_VALUE));
        float dimension3 = typedArrayL.getDimension(41, DefinitionKt.NO_Float_VALUE);
        if (fVar.k1 != dimension3) {
            fVar.k1 = dimension3;
            fVar.invalidateSelf();
            fVar.C();
        }
        float dimension4 = typedArrayL.getDimension(40, DefinitionKt.NO_Float_VALUE);
        if (fVar.l1 != dimension4) {
            fVar.l1 = dimension4;
            fVar.invalidateSelf();
            fVar.C();
        }
        fVar.S(typedArrayL.getDimension(29, DefinitionKt.NO_Float_VALUE));
        fVar.Q(typedArrayL.getDimension(27, DefinitionKt.NO_Float_VALUE));
        float dimension5 = typedArrayL.getDimension(13, DefinitionKt.NO_Float_VALUE);
        if (fVar.o1 != dimension5) {
            fVar.o1 = dimension5;
            fVar.invalidateSelf();
            fVar.C();
        }
        fVar.O1 = typedArrayL.getDimensionPixelSize(4, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        typedArrayL.recycle();
        com.google.android.material.internal.p.c(context2, attributeSet, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action);
        com.google.android.material.internal.p.d(context2, attributeSet, iArr, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action, new int[0]);
        TypedArray typedArrayObtainStyledAttributes = context2.obtainStyledAttributes(attributeSet, iArr, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action);
        this.o = typedArrayObtainStyledAttributes.getBoolean(32, false);
        this.q = (int) Math.ceil(typedArrayObtainStyledAttributes.getDimension(20, (float) Math.ceil(com.google.android.material.internal.p.g(getContext(), 48))));
        typedArrayObtainStyledAttributes.recycle();
        setChipDrawable(fVar);
        fVar.l(L.e(this));
        com.google.android.material.internal.p.c(context2, attributeSet, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action);
        com.google.android.material.internal.p.d(context2, attributeSet, iArr, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action, new int[0]);
        TypedArray typedArrayObtainStyledAttributes2 = context2.obtainStyledAttributes(attributeSet, iArr, com.quizlet.quizletandroid.R.attr.chipStyle, com.quizlet.quizletandroid.R.style.Widget_MaterialComponents_Chip_Action);
        boolean zHasValue = typedArrayObtainStyledAttributes2.hasValue(37);
        typedArrayObtainStyledAttributes2.recycle();
        this.s = new d(this, this);
        d();
        if (!zHasValue) {
            setOutlineProvider(new c(this));
        }
        setChecked(this.k);
        setText(fVar.F);
        setEllipsize(fVar.M1);
        g();
        if (!this.e.N1) {
            setLines(1);
            setHorizontallyScrolling(true);
        }
        setGravity(8388627);
        f();
        if (this.o) {
            setMinHeight(this.q);
        }
        this.p = getLayoutDirection();
        super.setOnCheckedChangeListener(new a(this, 0));
    }

    public void setCloseIconVisible(boolean z2) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.U(z2);
        }
        d();
    }

    public void setCheckedIconVisible(boolean z2) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.H(z2);
        }
    }

    public void setChipIconVisible(boolean z2) {
        f fVar = this.e;
        if (fVar != null) {
            fVar.M(z2);
        }
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesRelativeWithIntrinsicBounds(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        if (drawable != null) {
            throw new UnsupportedOperationException("Please set start drawable using R.attr#chipIcon.");
        }
        if (drawable3 == null) {
            super.setCompoundDrawablesRelativeWithIntrinsicBounds(drawable, drawable2, drawable3, drawable4);
            return;
        }
        throw new UnsupportedOperationException("Please set end drawable using R.attr#closeIcon.");
    }

    @Override // android.widget.TextView
    public final void setCompoundDrawablesWithIntrinsicBounds(Drawable drawable, Drawable drawable2, Drawable drawable3, Drawable drawable4) {
        if (drawable != null) {
            throw new UnsupportedOperationException("Please set left drawable using R.attr#chipIcon.");
        }
        if (drawable3 == null) {
            super.setCompoundDrawablesWithIntrinsicBounds(drawable, drawable2, drawable3, drawable4);
            return;
        }
        throw new UnsupportedOperationException("Please set right drawable using R.attr#closeIcon.");
    }

    @Override // android.widget.TextView
    public final void setTextAppearance(Context context, int i) {
        super.setTextAppearance(context, i);
        f fVar = this.e;
        if (fVar != null) {
            Context context2 = fVar.p1;
            fVar.v1.b(new com.google.android.material.resources.e(context2, i), context2);
        }
        g();
    }

    @Override // android.widget.TextView
    public void setTextAppearance(int i) {
        super.setTextAppearance(i);
        f fVar = this.e;
        if (fVar != null) {
            Context context = fVar.p1;
            fVar.v1.b(new com.google.android.material.resources.e(context, i), context);
        }
        g();
    }
}
