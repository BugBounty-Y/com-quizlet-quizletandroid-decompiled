package com.google.android.material.appbar;

import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.text.StaticLayout;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.D0;
import androidx.core.view.J;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class CollapsingToolbarLayout extends FrameLayout {
    public D0 A;
    public int B;
    public boolean C;
    public int D;
    public boolean E;
    public boolean a;
    public final int b;
    public ViewGroup c;
    public View d;
    public View e;
    public int f;
    public int g;
    public int h;
    public int i;
    public final Rect j;
    public final com.google.android.material.internal.b k;
    public final com.google.android.material.elevation.a l;
    public boolean m;
    public boolean n;
    public Drawable o;
    public Drawable p;
    public int q;
    public boolean r;
    public ValueAnimator s;
    public long t;
    public final TimeInterpolator u;
    public final TimeInterpolator v;
    public int w;
    public i x;
    public int y;
    public int z;

    public CollapsingToolbarLayout(@NonNull Context context) {
        this(context, null);
    }

    public static n b(View view) {
        n nVar = (n) view.getTag(R.id.view_offset_helper);
        if (nVar != null) {
            return nVar;
        }
        n nVar2 = new n(view);
        view.setTag(R.id.view_offset_helper, nVar2);
        return nVar2;
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x0020  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private int getDefaultContentScrimColorForTitleCollapseFadeMode() throws android.content.res.Resources.NotFoundException {
        /*
            r3 = this;
            android.content.Context r0 = r3.getContext()
            r1 = 2130969238(0x7f040296, float:1.7547152E38)
            android.util.TypedValue r1 = com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4.b(r0, r1)
            if (r1 != 0) goto Le
            goto L20
        Le:
            int r2 = r1.resourceId
            if (r2 == 0) goto L17
            android.content.res.ColorStateList r0 = androidx.core.content.c.c(r0, r2)
            goto L21
        L17:
            int r0 = r1.data
            if (r0 == 0) goto L20
            android.content.res.ColorStateList r0 = android.content.res.ColorStateList.valueOf(r0)
            goto L21
        L20:
            r0 = 0
        L21:
            if (r0 == 0) goto L28
            int r0 = r0.getDefaultColor()
            return r0
        L28:
            android.content.res.Resources r0 = r3.getResources()
            r1 = 2131165450(0x7f07010a, float:1.7945117E38)
            float r0 = r0.getDimension(r1)
            com.google.android.material.elevation.a r1 = r3.l
            int r2 = r1.d
            int r0 = r1.a(r0, r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.appbar.CollapsingToolbarLayout.getDefaultContentScrimColorForTitleCollapseFadeMode():int");
    }

    public final void a() {
        if (this.a) {
            ViewGroup viewGroup = null;
            this.c = null;
            this.d = null;
            int i = this.b;
            if (i != -1) {
                ViewGroup viewGroup2 = (ViewGroup) findViewById(i);
                this.c = viewGroup2;
                if (viewGroup2 != null) {
                    ViewParent parent = viewGroup2.getParent();
                    View view = viewGroup2;
                    while (parent != this && parent != null) {
                        if (parent instanceof View) {
                            view = (View) parent;
                        }
                        parent = parent.getParent();
                        view = view;
                    }
                    this.d = view;
                }
            }
            if (this.c == null) {
                int childCount = getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    View childAt = getChildAt(i2);
                    if ((childAt instanceof Toolbar) || (childAt instanceof android.widget.Toolbar)) {
                        viewGroup = (ViewGroup) childAt;
                        break;
                    }
                }
                this.c = viewGroup;
            }
            c();
            this.a = false;
        }
    }

    public final void c() {
        View view;
        if (!this.m && (view = this.e) != null) {
            ViewParent parent = view.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(this.e);
            }
        }
        if (!this.m || this.c == null) {
            return;
        }
        if (this.e == null) {
            this.e = new View(getContext());
        }
        if (this.e.getParent() == null) {
            this.c.addView(this.e, -1, -1);
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof h;
    }

    public final void d() {
        if (this.o == null && this.p == null) {
            return;
        }
        setScrimsShown(getHeight() + this.y < getScrimVisibleHeightTrigger());
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        Drawable drawable;
        super.draw(canvas);
        a();
        if (this.c == null && (drawable = this.o) != null && this.q > 0) {
            drawable.mutate().setAlpha(this.q);
            this.o.draw(canvas);
        }
        if (this.m && this.n) {
            ViewGroup viewGroup = this.c;
            com.google.android.material.internal.b bVar = this.k;
            if (viewGroup == null || this.o == null || this.q <= 0 || this.z != 1 || bVar.b >= bVar.e) {
                bVar.d(canvas);
            } else {
                int iSave = canvas.save();
                canvas.clipRect(this.o.getBounds(), Region.Op.DIFFERENCE);
                bVar.d(canvas);
                canvas.restoreToCount(iSave);
            }
        }
        if (this.p == null || this.q <= 0) {
            return;
        }
        D0 d0 = this.A;
        int iD = d0 != null ? d0.d() : 0;
        if (iD > 0) {
            this.p.setBounds(0, -this.y, getWidth(), iD - this.y);
            this.p.mutate().setAlpha(this.q);
            this.p.draw(canvas);
        }
    }

    @Override // android.view.ViewGroup
    public final boolean drawChild(Canvas canvas, View view, long j) {
        boolean z;
        View view2;
        Drawable drawable = this.o;
        if (drawable == null || this.q <= 0 || ((view2 = this.d) == null || view2 == this ? view != this.c : view != view2)) {
            z = false;
        } else {
            int width = getWidth();
            int height = getHeight();
            if (this.z == 1 && view != null && this.m) {
                height = view.getBottom();
            }
            drawable.setBounds(0, 0, width, height);
            this.o.mutate().setAlpha(this.q);
            this.o.draw(canvas);
            z = true;
        }
        return super.drawChild(canvas, view, j) || z;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void drawableStateChanged() {
        ColorStateList colorStateList;
        super.drawableStateChanged();
        int[] drawableState = getDrawableState();
        Drawable drawable = this.p;
        boolean z = false;
        boolean state = (drawable == null || !drawable.isStateful()) ? false : drawable.setState(drawableState);
        Drawable drawable2 = this.o;
        if (drawable2 != null && drawable2.isStateful()) {
            state |= drawable2.setState(drawableState);
        }
        com.google.android.material.internal.b bVar = this.k;
        if (bVar != null) {
            bVar.R = drawableState;
            ColorStateList colorStateList2 = bVar.o;
            if ((colorStateList2 != null && colorStateList2.isStateful()) || ((colorStateList = bVar.n) != null && colorStateList.isStateful())) {
                bVar.i(false);
                z = true;
            }
            state |= z;
        }
        if (state) {
            invalidate();
        }
    }

    public final void e(int i, int i2, int i3, int i4, boolean z) {
        View view;
        int titleMarginBottom;
        int titleMarginEnd;
        int titleMarginTop;
        if (!this.m || (view = this.e) == null) {
            return;
        }
        WeakHashMap weakHashMap = V.a;
        int titleMarginStart = 0;
        boolean z2 = view.isAttachedToWindow() && this.e.getVisibility() == 0;
        this.n = z2;
        if (z2 || z) {
            boolean z3 = getLayoutDirection() == 1;
            View view2 = this.d;
            if (view2 == null) {
                view2 = this.c;
            }
            int height = ((getHeight() - b(view2).b) - view2.getHeight()) - ((FrameLayout.LayoutParams) ((h) view2.getLayoutParams())).bottomMargin;
            View view3 = this.e;
            Rect rect = this.j;
            com.google.android.material.internal.c.a(this, view3, rect);
            ViewGroup viewGroup = this.c;
            if (viewGroup instanceof Toolbar) {
                Toolbar toolbar = (Toolbar) viewGroup;
                titleMarginStart = toolbar.getTitleMarginStart();
                titleMarginEnd = toolbar.getTitleMarginEnd();
                titleMarginTop = toolbar.getTitleMarginTop();
                titleMarginBottom = toolbar.getTitleMarginBottom();
            } else if (viewGroup instanceof android.widget.Toolbar) {
                android.widget.Toolbar toolbar2 = (android.widget.Toolbar) viewGroup;
                titleMarginStart = toolbar2.getTitleMarginStart();
                titleMarginEnd = toolbar2.getTitleMarginEnd();
                titleMarginTop = toolbar2.getTitleMarginTop();
                titleMarginBottom = toolbar2.getTitleMarginBottom();
            } else {
                titleMarginBottom = 0;
                titleMarginEnd = 0;
                titleMarginTop = 0;
            }
            int i5 = rect.left + (z3 ? titleMarginEnd : titleMarginStart);
            int i6 = rect.top + height + titleMarginTop;
            int i7 = rect.right;
            if (!z3) {
                titleMarginStart = titleMarginEnd;
            }
            int i8 = i7 - titleMarginStart;
            int i9 = (rect.bottom + height) - titleMarginBottom;
            com.google.android.material.internal.b bVar = this.k;
            Rect rect2 = bVar.h;
            if (rect2.left != i5 || rect2.top != i6 || rect2.right != i8 || rect2.bottom != i9) {
                rect2.set(i5, i6, i8, i9);
                bVar.S = true;
            }
            int i10 = z3 ? this.h : this.f;
            int i11 = rect.top + this.g;
            int i12 = (i3 - i) - (z3 ? this.f : this.h);
            int i13 = (i4 - i2) - this.i;
            Rect rect3 = bVar.g;
            if (rect3.left != i10 || rect3.top != i11 || rect3.right != i12 || rect3.bottom != i13) {
                rect3.set(i10, i11, i12, i13);
                bVar.S = true;
            }
            bVar.i(z);
        }
    }

    public final void f() {
        if (this.c != null && this.m && TextUtils.isEmpty(this.k.G)) {
            ViewGroup viewGroup = this.c;
            setTitle(viewGroup instanceof Toolbar ? ((Toolbar) viewGroup).getTitle() : viewGroup instanceof android.widget.Toolbar ? ((android.widget.Toolbar) viewGroup).getTitle() : null);
        }
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        h hVar = new h(-1, -1);
        hVar.a = 0;
        hVar.b = 0.5f;
        return hVar;
    }

    public int getCollapsedTitleGravity() {
        return this.k.k;
    }

    public float getCollapsedTitleTextSize() {
        return this.k.m;
    }

    @NonNull
    public Typeface getCollapsedTitleTypeface() {
        Typeface typeface = this.k.w;
        return typeface != null ? typeface : Typeface.DEFAULT;
    }

    public Drawable getContentScrim() {
        return this.o;
    }

    public int getExpandedTitleGravity() {
        return this.k.j;
    }

    public int getExpandedTitleMarginBottom() {
        return this.i;
    }

    public int getExpandedTitleMarginEnd() {
        return this.h;
    }

    public int getExpandedTitleMarginStart() {
        return this.f;
    }

    public int getExpandedTitleMarginTop() {
        return this.g;
    }

    public float getExpandedTitleTextSize() {
        return this.k.l;
    }

    @NonNull
    public Typeface getExpandedTitleTypeface() {
        Typeface typeface = this.k.z;
        return typeface != null ? typeface : Typeface.DEFAULT;
    }

    public int getHyphenationFrequency() {
        return this.k.q0;
    }

    public int getLineCount() {
        StaticLayout staticLayout = this.k.i0;
        if (staticLayout != null) {
            return staticLayout.getLineCount();
        }
        return 0;
    }

    public float getLineSpacingAdd() {
        return this.k.i0.getSpacingAdd();
    }

    public float getLineSpacingMultiplier() {
        return this.k.i0.getSpacingMultiplier();
    }

    public int getMaxLines() {
        return this.k.n0;
    }

    public int getScrimAlpha() {
        return this.q;
    }

    public long getScrimAnimationDuration() {
        return this.t;
    }

    public int getScrimVisibleHeightTrigger() {
        int i = this.w;
        if (i >= 0) {
            return i + this.B + this.D;
        }
        D0 d0 = this.A;
        int iD = d0 != null ? d0.d() : 0;
        WeakHashMap weakHashMap = V.a;
        int minimumHeight = getMinimumHeight();
        return minimumHeight > 0 ? Math.min((minimumHeight * 2) + iD, getHeight()) : getHeight() / 3;
    }

    public Drawable getStatusBarScrim() {
        return this.p;
    }

    public CharSequence getTitle() {
        if (this.m) {
            return this.k.G;
        }
        return null;
    }

    public int getTitleCollapseMode() {
        return this.z;
    }

    public TimeInterpolator getTitlePositionInterpolator() {
        return this.k.V;
    }

    @NonNull
    public TextUtils.TruncateAt getTitleTextEllipsize() {
        return this.k.F;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        ViewParent parent = getParent();
        if (parent instanceof AppBarLayout) {
            AppBarLayout appBarLayout = (AppBarLayout) parent;
            if (this.z == 1) {
                appBarLayout.setLiftOnScroll(false);
            }
            WeakHashMap weakHashMap = V.a;
            setFitsSystemWindows(appBarLayout.getFitsSystemWindows());
            if (this.x == null) {
                this.x = new i(this);
            }
            appBarLayout.a(this.x);
            J.c(this);
        }
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        this.k.h(configuration);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        ArrayList arrayList;
        ViewParent parent = getParent();
        i iVar = this.x;
        if (iVar != null && (parent instanceof AppBarLayout) && (arrayList = ((AppBarLayout) parent).h) != null) {
            arrayList.remove(iVar);
        }
        super.onDetachedFromWindow();
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        D0 d0 = this.A;
        if (d0 != null) {
            int iD = d0.d();
            int childCount = getChildCount();
            for (int i5 = 0; i5 < childCount; i5++) {
                View childAt = getChildAt(i5);
                WeakHashMap weakHashMap = V.a;
                if (!childAt.getFitsSystemWindows() && childAt.getTop() < iD) {
                    childAt.offsetTopAndBottom(iD);
                }
            }
        }
        int childCount2 = getChildCount();
        for (int i6 = 0; i6 < childCount2; i6++) {
            n nVarB = b(getChildAt(i6));
            View view = nVarB.a;
            nVarB.b = view.getTop();
            nVarB.c = view.getLeft();
        }
        e(i, i2, i3, i4, false);
        f();
        d();
        int childCount3 = getChildCount();
        for (int i7 = 0; i7 < childCount3; i7++) {
            b(getChildAt(i7)).a();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x007f  */
    @Override // android.widget.FrameLayout, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onMeasure(int r10, int r11) {
        /*
            r9 = this;
            r9.a()
            super.onMeasure(r10, r11)
            int r11 = android.view.View.MeasureSpec.getMode(r11)
            androidx.core.view.D0 r0 = r9.A
            if (r0 == 0) goto L13
            int r0 = r0.d()
            goto L14
        L13:
            r0 = 0
        L14:
            r1 = 1073741824(0x40000000, float:2.0)
            if (r11 == 0) goto L1c
            boolean r11 = r9.C
            if (r11 == 0) goto L2c
        L1c:
            if (r0 <= 0) goto L2c
            r9.B = r0
            int r11 = r9.getMeasuredHeight()
            int r11 = r11 + r0
            int r11 = android.view.View.MeasureSpec.makeMeasureSpec(r11, r1)
            super.onMeasure(r10, r11)
        L2c:
            boolean r11 = r9.E
            if (r11 == 0) goto L7f
            com.google.android.material.internal.b r11 = r9.k
            int r0 = r11.n0
            r2 = 1
            if (r0 <= r2) goto L7f
            r9.f()
            int r6 = r9.getMeasuredWidth()
            int r7 = r9.getMeasuredHeight()
            r4 = 0
            r5 = 0
            r8 = 1
            r3 = r9
            r3.e(r4, r5, r6, r7, r8)
            int r0 = r11.p
            if (r0 <= r2) goto L80
            android.text.TextPaint r4 = r11.U
            float r5 = r11.l
            r4.setTextSize(r5)
            android.graphics.Typeface r5 = r11.z
            r4.setTypeface(r5)
            float r11 = r11.g0
            r4.setLetterSpacing(r11)
            float r11 = r4.ascent()
            float r11 = -r11
            float r4 = r4.descent()
            float r4 = r4 + r11
            int r11 = java.lang.Math.round(r4)
            int r0 = r0 - r2
            int r0 = r0 * r11
            r3.D = r0
            int r11 = r9.getMeasuredHeight()
            int r0 = r3.D
            int r11 = r11 + r0
            int r11 = android.view.View.MeasureSpec.makeMeasureSpec(r11, r1)
            super.onMeasure(r10, r11)
            goto L80
        L7f:
            r3 = r9
        L80:
            android.view.ViewGroup r10 = r3.c
            if (r10 == 0) goto Lc4
            android.view.View r11 = r3.d
            if (r11 == 0) goto La8
            if (r11 != r3) goto L8b
            goto La8
        L8b:
            android.view.ViewGroup$LayoutParams r10 = r11.getLayoutParams()
            boolean r0 = r10 instanceof android.view.ViewGroup.MarginLayoutParams
            if (r0 == 0) goto La0
            android.view.ViewGroup$MarginLayoutParams r10 = (android.view.ViewGroup.MarginLayoutParams) r10
            int r11 = r11.getMeasuredHeight()
            int r0 = r10.topMargin
            int r11 = r11 + r0
            int r10 = r10.bottomMargin
            int r11 = r11 + r10
            goto La4
        La0:
            int r11 = r11.getMeasuredHeight()
        La4:
            r9.setMinimumHeight(r11)
            return
        La8:
            android.view.ViewGroup$LayoutParams r11 = r10.getLayoutParams()
            boolean r0 = r11 instanceof android.view.ViewGroup.MarginLayoutParams
            if (r0 == 0) goto Lbd
            android.view.ViewGroup$MarginLayoutParams r11 = (android.view.ViewGroup.MarginLayoutParams) r11
            int r10 = r10.getMeasuredHeight()
            int r0 = r11.topMargin
            int r10 = r10 + r0
            int r11 = r11.bottomMargin
            int r10 = r10 + r11
            goto Lc1
        Lbd:
            int r10 = r10.getMeasuredHeight()
        Lc1:
            r9.setMinimumHeight(r10)
        Lc4:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.appbar.CollapsingToolbarLayout.onMeasure(int, int):void");
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        Drawable drawable = this.o;
        if (drawable != null) {
            ViewGroup viewGroup = this.c;
            if (this.z == 1 && viewGroup != null && this.m) {
                i2 = viewGroup.getBottom();
            }
            drawable.setBounds(0, 0, i, i2);
        }
    }

    public void setCollapsedTitleGravity(int i) {
        this.k.l(i);
    }

    public void setCollapsedTitleTextAppearance(int i) {
        this.k.k(i);
    }

    public void setCollapsedTitleTextColor(@NonNull ColorStateList colorStateList) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.o != colorStateList) {
            bVar.o = colorStateList;
            bVar.i(false);
        }
    }

    public void setCollapsedTitleTextSize(float f) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.m != f) {
            bVar.m = f;
            bVar.i(false);
        }
    }

    public void setCollapsedTitleTypeface(Typeface typeface) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.m(typeface)) {
            bVar.i(false);
        }
    }

    public void setContentScrim(Drawable drawable) {
        Drawable drawable2 = this.o;
        if (drawable2 != drawable) {
            if (drawable2 != null) {
                drawable2.setCallback(null);
            }
            Drawable drawableMutate = drawable != null ? drawable.mutate() : null;
            this.o = drawableMutate;
            if (drawableMutate != null) {
                int width = getWidth();
                int height = getHeight();
                ViewGroup viewGroup = this.c;
                if (this.z == 1 && viewGroup != null && this.m) {
                    height = viewGroup.getBottom();
                }
                drawableMutate.setBounds(0, 0, width, height);
                this.o.setCallback(this);
                this.o.setAlpha(this.q);
            }
            WeakHashMap weakHashMap = V.a;
            postInvalidateOnAnimation();
        }
    }

    public void setContentScrimColor(int i) {
        setContentScrim(new ColorDrawable(i));
    }

    public void setContentScrimResource(int i) {
        setContentScrim(getContext().getDrawable(i));
    }

    public void setExpandedTitleColor(int i) {
        setExpandedTitleTextColor(ColorStateList.valueOf(i));
    }

    public void setExpandedTitleGravity(int i) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.j != i) {
            bVar.j = i;
            bVar.i(false);
        }
    }

    public void setExpandedTitleMarginBottom(int i) {
        this.i = i;
        requestLayout();
    }

    public void setExpandedTitleMarginEnd(int i) {
        this.h = i;
        requestLayout();
    }

    public void setExpandedTitleMarginStart(int i) {
        this.f = i;
        requestLayout();
    }

    public void setExpandedTitleMarginTop(int i) {
        this.g = i;
        requestLayout();
    }

    public void setExpandedTitleTextAppearance(int i) {
        this.k.n(i);
    }

    public void setExpandedTitleTextColor(@NonNull ColorStateList colorStateList) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.n != colorStateList) {
            bVar.n = colorStateList;
            bVar.i(false);
        }
    }

    public void setExpandedTitleTextSize(float f) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.l != f) {
            bVar.l = f;
            bVar.i(false);
        }
    }

    public void setExpandedTitleTypeface(Typeface typeface) {
        com.google.android.material.internal.b bVar = this.k;
        if (bVar.o(typeface)) {
            bVar.i(false);
        }
    }

    public void setExtraMultilineHeightEnabled(boolean z) {
        this.E = z;
    }

    public void setForceApplySystemWindowInsetTop(boolean z) {
        this.C = z;
    }

    public void setHyphenationFrequency(int i) {
        this.k.q0 = i;
    }

    public void setLineSpacingAdd(float f) {
        this.k.o0 = f;
    }

    public void setLineSpacingMultiplier(float f) {
        this.k.p0 = f;
    }

    public void setMaxLines(int i) {
        com.google.android.material.internal.b bVar = this.k;
        if (i != bVar.n0) {
            bVar.n0 = i;
            Bitmap bitmap = bVar.K;
            if (bitmap != null) {
                bitmap.recycle();
                bVar.K = null;
            }
            bVar.i(false);
        }
    }

    public void setRtlTextDirectionHeuristicsEnabled(boolean z) {
        this.k.J = z;
    }

    public void setScrimAlpha(int i) {
        ViewGroup viewGroup;
        if (i != this.q) {
            if (this.o != null && (viewGroup = this.c) != null) {
                WeakHashMap weakHashMap = V.a;
                viewGroup.postInvalidateOnAnimation();
            }
            this.q = i;
            WeakHashMap weakHashMap2 = V.a;
            postInvalidateOnAnimation();
        }
    }

    public void setScrimAnimationDuration(long j) {
        this.t = j;
    }

    public void setScrimVisibleHeightTrigger(int i) {
        if (this.w != i) {
            this.w = i;
            d();
        }
    }

    public void setScrimsShown(boolean z) {
        WeakHashMap weakHashMap = V.a;
        boolean z2 = isLaidOut() && !isInEditMode();
        if (this.r != z) {
            if (z2) {
                int i = z ? 255 : 0;
                a();
                ValueAnimator valueAnimator = this.s;
                if (valueAnimator == null) {
                    ValueAnimator valueAnimator2 = new ValueAnimator();
                    this.s = valueAnimator2;
                    valueAnimator2.setInterpolator(i > this.q ? this.u : this.v);
                    this.s.addUpdateListener(new g(this, 0));
                } else if (valueAnimator.isRunning()) {
                    this.s.cancel();
                }
                this.s.setDuration(this.t);
                this.s.setIntValues(this.q, i);
                this.s.start();
            } else {
                setScrimAlpha(z ? 255 : 0);
            }
            this.r = z;
        }
    }

    public void setStaticLayoutBuilderConfigurer(j jVar) {
        com.google.android.material.internal.b bVar = this.k;
        if (jVar != null) {
            bVar.i(true);
        } else {
            bVar.getClass();
        }
    }

    public void setStatusBarScrim(Drawable drawable) {
        Drawable drawable2 = this.p;
        if (drawable2 != drawable) {
            if (drawable2 != null) {
                drawable2.setCallback(null);
            }
            Drawable drawableMutate = drawable != null ? drawable.mutate() : null;
            this.p = drawableMutate;
            if (drawableMutate != null) {
                if (drawableMutate.isStateful()) {
                    this.p.setState(getDrawableState());
                }
                Drawable drawable3 = this.p;
                WeakHashMap weakHashMap = V.a;
                drawable3.setLayoutDirection(getLayoutDirection());
                this.p.setVisible(getVisibility() == 0, false);
                this.p.setCallback(this);
                this.p.setAlpha(this.q);
            }
            WeakHashMap weakHashMap2 = V.a;
            postInvalidateOnAnimation();
        }
    }

    public void setStatusBarScrimColor(int i) {
        setStatusBarScrim(new ColorDrawable(i));
    }

    public void setStatusBarScrimResource(int i) {
        setStatusBarScrim(getContext().getDrawable(i));
    }

    public void setTitle(CharSequence charSequence) {
        com.google.android.material.internal.b bVar = this.k;
        if (charSequence == null || !TextUtils.equals(bVar.G, charSequence)) {
            bVar.G = charSequence;
            bVar.H = null;
            Bitmap bitmap = bVar.K;
            if (bitmap != null) {
                bitmap.recycle();
                bVar.K = null;
            }
            bVar.i(false);
        }
        setContentDescription(getTitle());
    }

    public void setTitleCollapseMode(int i) {
        this.z = i;
        boolean z = i == 1;
        this.k.c = z;
        ViewParent parent = getParent();
        if (parent instanceof AppBarLayout) {
            AppBarLayout appBarLayout = (AppBarLayout) parent;
            if (this.z == 1) {
                appBarLayout.setLiftOnScroll(false);
            }
        }
        if (z && this.o == null) {
            setContentScrimColor(getDefaultContentScrimColorForTitleCollapseFadeMode());
        }
    }

    public void setTitleEllipsize(@NonNull TextUtils.TruncateAt truncateAt) {
        com.google.android.material.internal.b bVar = this.k;
        bVar.F = truncateAt;
        bVar.i(false);
    }

    public void setTitleEnabled(boolean z) {
        if (z != this.m) {
            this.m = z;
            setContentDescription(getTitle());
            c();
            requestLayout();
        }
    }

    public void setTitlePositionInterpolator(TimeInterpolator timeInterpolator) {
        com.google.android.material.internal.b bVar = this.k;
        bVar.V = timeInterpolator;
        bVar.i(false);
    }

    @Override // android.view.View
    public void setVisibility(int i) {
        super.setVisibility(i);
        boolean z = i == 0;
        Drawable drawable = this.p;
        if (drawable != null && drawable.isVisible() != z) {
            this.p.setVisible(z, false);
        }
        Drawable drawable2 = this.o;
        if (drawable2 == null || drawable2.isVisible() == z) {
            return;
        }
        this.o.setVisible(z, false);
    }

    @Override // android.view.View
    public final boolean verifyDrawable(Drawable drawable) {
        return super.verifyDrawable(drawable) || drawable == this.o || drawable == this.p;
    }

    public CollapsingToolbarLayout(@NonNull Context context, AttributeSet attributeSet) {
        int i;
        ColorStateList colorStateListA;
        ColorStateList colorStateListA2;
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, R.attr.collapsingToolbarLayoutStyle, R.style.Widget_Design_CollapsingToolbar), attributeSet, R.attr.collapsingToolbarLayoutStyle);
        this.a = true;
        this.j = new Rect();
        this.w = -1;
        this.B = 0;
        this.D = 0;
        Context context2 = getContext();
        com.google.android.material.internal.b bVar = new com.google.android.material.internal.b(this);
        this.k = bVar;
        bVar.W = com.google.android.material.animation.a.e;
        bVar.i(false);
        bVar.J = false;
        this.l = new com.google.android.material.elevation.a(context2);
        TypedArray typedArrayL = p.l(context2, attributeSet, com.google.android.material.a.l, R.attr.collapsingToolbarLayoutStyle, R.style.Widget_Design_CollapsingToolbar, new int[0]);
        int i2 = typedArrayL.getInt(4, 8388691);
        if (bVar.j != i2) {
            bVar.j = i2;
            bVar.i(false);
        }
        bVar.l(typedArrayL.getInt(0, 8388627));
        int dimensionPixelSize = typedArrayL.getDimensionPixelSize(5, 0);
        this.i = dimensionPixelSize;
        this.h = dimensionPixelSize;
        this.g = dimensionPixelSize;
        this.f = dimensionPixelSize;
        if (typedArrayL.hasValue(8)) {
            this.f = typedArrayL.getDimensionPixelSize(8, 0);
        }
        if (typedArrayL.hasValue(7)) {
            this.h = typedArrayL.getDimensionPixelSize(7, 0);
        }
        if (typedArrayL.hasValue(9)) {
            this.g = typedArrayL.getDimensionPixelSize(9, 0);
        }
        if (typedArrayL.hasValue(6)) {
            this.i = typedArrayL.getDimensionPixelSize(6, 0);
        }
        this.m = typedArrayL.getBoolean(20, true);
        setTitle(typedArrayL.getText(18));
        bVar.n(R.style.TextAppearance_Design_CollapsingToolbar_Expanded);
        bVar.k(R.style.TextAppearance_AppCompat_Widget_ActionBar_Title);
        if (typedArrayL.hasValue(10)) {
            bVar.n(typedArrayL.getResourceId(10, 0));
        }
        if (typedArrayL.hasValue(1)) {
            bVar.k(typedArrayL.getResourceId(1, 0));
        }
        if (typedArrayL.hasValue(22)) {
            int i3 = typedArrayL.getInt(22, -1);
            setTitleEllipsize(i3 != 0 ? i3 != 1 ? i3 != 3 ? TextUtils.TruncateAt.END : TextUtils.TruncateAt.MARQUEE : TextUtils.TruncateAt.MIDDLE : TextUtils.TruncateAt.START);
        }
        if (typedArrayL.hasValue(11) && bVar.n != (colorStateListA2 = AbstractC3442d4.a(context2, typedArrayL, 11))) {
            bVar.n = colorStateListA2;
            bVar.i(false);
        }
        if (typedArrayL.hasValue(2) && bVar.o != (colorStateListA = AbstractC3442d4.a(context2, typedArrayL, 2))) {
            bVar.o = colorStateListA;
            bVar.i(false);
        }
        this.w = typedArrayL.getDimensionPixelSize(16, -1);
        if (typedArrayL.hasValue(14) && (i = typedArrayL.getInt(14, 1)) != bVar.n0) {
            bVar.n0 = i;
            Bitmap bitmap = bVar.K;
            if (bitmap != null) {
                bitmap.recycle();
                bVar.K = null;
            }
            bVar.i(false);
        }
        if (typedArrayL.hasValue(21)) {
            bVar.V = AnimationUtils.loadInterpolator(context2, typedArrayL.getResourceId(21, 0));
            bVar.i(false);
        }
        this.t = typedArrayL.getInt(15, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR);
        this.u = AbstractC3430b4.e(context2, R.attr.motionEasingStandardInterpolator, com.google.android.material.animation.a.c);
        this.v = AbstractC3430b4.e(context2, R.attr.motionEasingStandardInterpolator, com.google.android.material.animation.a.d);
        setContentScrim(typedArrayL.getDrawable(3));
        setStatusBarScrim(typedArrayL.getDrawable(17));
        setTitleCollapseMode(typedArrayL.getInt(19, 0));
        this.b = typedArrayL.getResourceId(23, -1);
        this.C = typedArrayL.getBoolean(13, false);
        this.E = typedArrayL.getBoolean(12, false);
        typedArrayL.recycle();
        setWillNotDraw(false);
        com.google.android.gms.auth.api.signin.internal.h hVar = new com.google.android.gms.auth.api.signin.internal.h(this, 27);
        WeakHashMap weakHashMap = V.a;
        L.m(this, hVar);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final FrameLayout.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        Context context = getContext();
        h hVar = new h(context, attributeSet);
        hVar.a = 0;
        hVar.b = 0.5f;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, com.google.android.material.a.m);
        hVar.a = typedArrayObtainStyledAttributes.getInt(0, 0);
        hVar.b = typedArrayObtainStyledAttributes.getFloat(1, 0.5f);
        typedArrayObtainStyledAttributes.recycle();
        return hVar;
    }

    public void setCollapsedTitleTextColor(int i) {
        setCollapsedTitleTextColor(ColorStateList.valueOf(i));
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final FrameLayout.LayoutParams generateDefaultLayoutParams() {
        h hVar = new h(-1, -1);
        hVar.a = 0;
        hVar.b = 0.5f;
        return hVar;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        h hVar = new h(layoutParams);
        hVar.a = 0;
        hVar.b = 0.5f;
        return hVar;
    }
}
