package com.google.android.material.tabs;

import android.animation.Animator;
import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.FrameLayout;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.Q;
import androidx.appcompat.widget.D0;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.viewpager.widget.ViewPager;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3436c4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3442d4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class l extends HorizontalScrollView {
    public static final androidx.core.util.d j1 = new androidx.core.util.d(16);
    public final int A;
    public int B;
    public int C;
    public boolean D;
    public boolean E;
    public int F;
    public int G;
    public boolean H;
    public com.google.android.material.shape.e I;
    public final TimeInterpolator J;
    public d K;
    public final ArrayList L;
    public k M;
    public ValueAnimator V;
    public ViewPager W;
    public int a;
    public final ArrayList b;
    public g c;
    public androidx.viewpager.widget.a c1;
    public final f d;
    public D0 d1;
    public final int e;
    public h e1;
    public final int f;
    public c f1;
    public final int g;
    public boolean g1;
    public final int h;
    public int h1;
    public final int i;
    public final androidx.constraintlayout.core.d i1;
    public final int j;
    public final int k;
    public ColorStateList l;
    public ColorStateList m;
    public ColorStateList n;
    public Drawable o;
    public int p;
    public final PorterDuff.Mode q;
    public final float r;
    public final float s;
    public final int t;
    public int u;
    public final int v;
    public final int w;
    public final int x;
    public final int y;
    public int z;

    public l(@NonNull Context context) {
        this(context, null);
    }

    private int getDefaultHeight() {
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            g gVar = (g) arrayList.get(i);
            if (gVar != null && gVar.b != null && !TextUtils.isEmpty(gVar.c)) {
                return !this.D ? 72 : 48;
            }
        }
        return 48;
    }

    private int getTabMinWidth() {
        int i = this.v;
        if (i != -1) {
            return i;
        }
        int i2 = this.C;
        if (i2 == 0 || i2 == 2) {
            return this.x;
        }
        return 0;
    }

    private int getTabScrollRange() {
        return Math.max(0, ((this.d.getWidth() - getWidth()) - getPaddingLeft()) - getPaddingRight());
    }

    private void setSelectedTabView(int i) {
        f fVar = this.d;
        int childCount = fVar.getChildCount();
        if (i < childCount) {
            int i2 = 0;
            while (i2 < childCount) {
                View childAt = fVar.getChildAt(i2);
                if ((i2 != i || childAt.isSelected()) && (i2 == i || !childAt.isSelected())) {
                    childAt.setSelected(i2 == i);
                    childAt.setActivated(i2 == i);
                } else {
                    childAt.setSelected(i2 == i);
                    childAt.setActivated(i2 == i);
                    if (childAt instanceof j) {
                        ((j) childAt).g();
                    }
                }
                i2++;
            }
        }
    }

    public void a(g gVar) {
        c(gVar, this.b.isEmpty());
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
    public final void addView(View view) {
        d(view);
    }

    public void b(g gVar, int i, boolean z) {
        if (gVar.g != this) {
            throw new IllegalArgumentException("Tab belongs to a different TabLayout.");
        }
        gVar.e = i;
        ArrayList arrayList = this.b;
        arrayList.add(i, gVar);
        int size = arrayList.size();
        int i2 = -1;
        for (int i3 = i + 1; i3 < size; i3++) {
            if (((g) arrayList.get(i3)).e == this.a) {
                i2 = i3;
            }
            ((g) arrayList.get(i3)).e = i3;
        }
        this.a = i2;
        j jVar = gVar.h;
        jVar.setSelected(false);
        jVar.setActivated(false);
        int i4 = gVar.e;
        LinearLayout.LayoutParams layoutParams = new LinearLayout.LayoutParams(-2, -1);
        if (this.C == 1 && this.z == 0) {
            layoutParams.width = 0;
            layoutParams.weight = 1.0f;
        } else {
            layoutParams.width = -2;
            layoutParams.weight = DefinitionKt.NO_Float_VALUE;
        }
        this.d.addView(jVar, i4, layoutParams);
        if (z) {
            l lVar = gVar.g;
            if (lVar == null) {
                throw new IllegalArgumentException("Tab not attached to a TabLayout");
            }
            lVar.m(gVar, true);
        }
    }

    public void c(g gVar, boolean z) {
        b(gVar, this.b.size(), z);
    }

    public final void d(View view) {
        if (!(view instanceof b)) {
            throw new IllegalArgumentException("Only TabItem instances can be added to TabLayout");
        }
        b bVar = (b) view;
        g gVarJ = j();
        CharSequence charSequence = bVar.a;
        if (charSequence != null) {
            gVarJ.a(charSequence);
        }
        Drawable drawable = bVar.b;
        if (drawable != null) {
            gVarJ.b = drawable;
            l lVar = gVarJ.g;
            if (lVar.z == 1 || lVar.C == 2) {
                lVar.q(true);
            }
            j jVar = gVarJ.h;
            if (jVar != null) {
                jVar.e();
            }
        }
        int i = bVar.c;
        if (i != 0) {
            gVarJ.f = LayoutInflater.from(gVarJ.h.getContext()).inflate(i, (ViewGroup) gVarJ.h, false);
            j jVar2 = gVarJ.h;
            if (jVar2 != null) {
                jVar2.e();
            }
        }
        if (!TextUtils.isEmpty(bVar.getContentDescription())) {
            gVarJ.d = bVar.getContentDescription();
            j jVar3 = gVarJ.h;
            if (jVar3 != null) {
                jVar3.e();
            }
        }
        a(gVarJ);
    }

    public final void e(int i) {
        if (i == -1) {
            return;
        }
        if (getWindowToken() != null) {
            WeakHashMap weakHashMap = V.a;
            if (isLaidOut()) {
                f fVar = this.d;
                int childCount = fVar.getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    if (fVar.getChildAt(i2).getWidth() > 0) {
                    }
                }
                int scrollX = getScrollX();
                int iG = g(DefinitionKt.NO_Float_VALUE, i);
                if (scrollX != iG) {
                    h();
                    this.V.setIntValues(scrollX, iG);
                    this.V.start();
                }
                ValueAnimator valueAnimator = fVar.a;
                if (valueAnimator != null && valueAnimator.isRunning() && fVar.b.a != i) {
                    fVar.a.cancel();
                }
                fVar.d(i, this.A, true);
                return;
            }
        }
        o(i, DefinitionKt.NO_Float_VALUE, true, true, true);
    }

    public final void f() {
        int i = this.C;
        int iMax = (i == 0 || i == 2) ? Math.max(0, this.y - this.e) : 0;
        WeakHashMap weakHashMap = V.a;
        f fVar = this.d;
        fVar.setPaddingRelative(iMax, 0, 0, 0);
        int i2 = this.C;
        if (i2 == 0) {
            int i3 = this.z;
            if (i3 == 0) {
                Log.w("TabLayout", "MODE_SCROLLABLE + GRAVITY_FILL is not supported, GRAVITY_START will be used instead");
            } else if (i3 == 1) {
                fVar.setGravity(1);
            } else if (i3 == 2) {
            }
            fVar.setGravity(8388611);
        } else if (i2 == 1 || i2 == 2) {
            if (this.z == 2) {
                Log.w("TabLayout", "GRAVITY_START is not supported with the current tab mode, GRAVITY_CENTER will be used instead");
            }
            fVar.setGravity(1);
        }
        q(true);
    }

    public final int g(float f, int i) {
        f fVar;
        View childAt;
        int i2 = this.C;
        if ((i2 != 0 && i2 != 2) || (childAt = (fVar = this.d).getChildAt(i)) == null) {
            return 0;
        }
        int i3 = i + 1;
        View childAt2 = i3 < fVar.getChildCount() ? fVar.getChildAt(i3) : null;
        int width = childAt.getWidth();
        int width2 = childAt2 != null ? childAt2.getWidth() : 0;
        int left = ((width / 2) + childAt.getLeft()) - (getWidth() / 2);
        int i4 = (int) ((width + width2) * 0.5f * f);
        WeakHashMap weakHashMap = V.a;
        return getLayoutDirection() == 0 ? left + i4 : left - i4;
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return generateDefaultLayoutParams();
    }

    public int getSelectedTabPosition() {
        g gVar = this.c;
        if (gVar != null) {
            return gVar.e;
        }
        return -1;
    }

    public int getTabCount() {
        return this.b.size();
    }

    public int getTabGravity() {
        return this.z;
    }

    public ColorStateList getTabIconTint() {
        return this.m;
    }

    public int getTabIndicatorAnimationMode() {
        return this.G;
    }

    public int getTabIndicatorGravity() {
        return this.B;
    }

    public int getTabMaxWidth() {
        return this.u;
    }

    public int getTabMode() {
        return this.C;
    }

    public ColorStateList getTabRippleColor() {
        return this.n;
    }

    @NonNull
    public Drawable getTabSelectedIndicator() {
        return this.o;
    }

    public ColorStateList getTabTextColors() {
        return this.l;
    }

    public final void h() {
        if (this.V == null) {
            ValueAnimator valueAnimator = new ValueAnimator();
            this.V = valueAnimator;
            valueAnimator.setInterpolator(this.J);
            this.V.setDuration(this.A);
            this.V.addUpdateListener(new com.google.android.material.appbar.g(this, 2));
        }
    }

    public final g i(int i) {
        if (i < 0 || i >= getTabCount()) {
            return null;
        }
        return (g) this.b.get(i);
    }

    public final g j() {
        g gVar = (g) j1.a();
        if (gVar == null) {
            gVar = new g();
            gVar.e = -1;
        }
        gVar.g = this;
        androidx.constraintlayout.core.d dVar = this.i1;
        j jVar = dVar != null ? (j) dVar.a() : null;
        if (jVar == null) {
            jVar = new j(this, getContext());
        }
        jVar.setTab(gVar);
        jVar.setFocusable(true);
        jVar.setMinimumWidth(getTabMinWidth());
        if (TextUtils.isEmpty(gVar.d)) {
            jVar.setContentDescription(gVar.c);
        } else {
            jVar.setContentDescription(gVar.d);
        }
        gVar.h = jVar;
        return gVar;
    }

    public final void k() {
        int currentItem;
        l();
        androidx.viewpager.widget.a aVar = this.c1;
        if (aVar != null) {
            int iC = aVar.c();
            for (int i = 0; i < iC; i++) {
                g gVarJ = j();
                gVarJ.a(this.c1.e(i));
                c(gVarJ, false);
            }
            ViewPager viewPager = this.W;
            if (viewPager == null || iC <= 0 || (currentItem = viewPager.getCurrentItem()) == getSelectedTabPosition() || currentItem >= getTabCount()) {
                return;
            }
            m(i(currentItem), true);
        }
    }

    public final void l() {
        f fVar = this.d;
        int childCount = fVar.getChildCount();
        while (true) {
            childCount--;
            if (childCount < 0) {
                break;
            }
            j jVar = (j) fVar.getChildAt(childCount);
            fVar.removeViewAt(childCount);
            if (jVar != null) {
                jVar.setTab(null);
                jVar.setSelected(false);
                this.i1.c(jVar);
            }
            requestLayout();
        }
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            g gVar = (g) it2.next();
            it2.remove();
            gVar.g = null;
            gVar.h = null;
            gVar.a = null;
            gVar.b = null;
            gVar.c = null;
            gVar.d = null;
            gVar.e = -1;
            gVar.f = null;
            j1.c(gVar);
        }
        this.c = null;
    }

    public final void m(g gVar, boolean z) {
        l lVar;
        g gVar2 = this.c;
        ArrayList arrayList = this.L;
        if (gVar2 == gVar) {
            if (gVar2 != null) {
                for (int size = arrayList.size() - 1; size >= 0; size--) {
                    ((d) arrayList.get(size)).a(gVar);
                }
                e(gVar.e);
                return;
            }
            return;
        }
        int i = gVar != null ? gVar.e : -1;
        if (z) {
            if ((gVar2 == null || gVar2.e == -1) && i != -1) {
                lVar = this;
                lVar.o(i, DefinitionKt.NO_Float_VALUE, true, true, true);
            } else {
                lVar = this;
                e(i);
            }
            if (i != -1) {
                setSelectedTabView(i);
            }
        } else {
            lVar = this;
        }
        lVar.c = gVar;
        if (gVar2 != null && gVar2.g != null) {
            for (int size2 = arrayList.size() - 1; size2 >= 0; size2--) {
                ((d) arrayList.get(size2)).c(gVar2);
            }
        }
        if (gVar != null) {
            for (int size3 = arrayList.size() - 1; size3 >= 0; size3--) {
                ((d) arrayList.get(size3)).b(gVar);
            }
        }
    }

    public final void n(androidx.viewpager.widget.a aVar, boolean z) {
        D0 d0;
        androidx.viewpager.widget.a aVar2 = this.c1;
        if (aVar2 != null && (d0 = this.d1) != null) {
            aVar2.a.unregisterObserver(d0);
        }
        this.c1 = aVar;
        if (z && aVar != null) {
            if (this.d1 == null) {
                this.d1 = new D0(this, 4);
            }
            aVar.a.registerObserver(this.d1);
        }
        k();
    }

    public final void o(int i, float f, boolean z, boolean z2, boolean z3) {
        float f2 = i + f;
        int iRound = Math.round(f2);
        if (iRound >= 0) {
            f fVar = this.d;
            if (iRound >= fVar.getChildCount()) {
                return;
            }
            if (z2) {
                fVar.b.a = Math.round(f2);
                ValueAnimator valueAnimator = fVar.a;
                if (valueAnimator != null && valueAnimator.isRunning()) {
                    fVar.a.cancel();
                }
                fVar.c(fVar.getChildAt(i), fVar.getChildAt(i + 1), f);
            }
            ValueAnimator valueAnimator2 = this.V;
            if (valueAnimator2 != null && valueAnimator2.isRunning()) {
                this.V.cancel();
            }
            int iG = g(f, i);
            int scrollX = getScrollX();
            boolean z4 = (i < getSelectedTabPosition() && iG >= scrollX) || (i > getSelectedTabPosition() && iG <= scrollX) || i == getSelectedTabPosition();
            WeakHashMap weakHashMap = V.a;
            if (getLayoutDirection() == 1) {
                z4 = (i < getSelectedTabPosition() && iG <= scrollX) || (i > getSelectedTabPosition() && iG >= scrollX) || i == getSelectedTabPosition();
            }
            if (z4 || this.h1 == 1 || z3) {
                if (i < 0) {
                    iG = 0;
                }
                scrollTo(iG, 0);
            }
            if (z) {
                setSelectedTabView(iRound);
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        AbstractC3466h4.c(this);
        if (this.W == null) {
            ViewParent parent = getParent();
            if (parent instanceof ViewPager) {
                p((ViewPager) parent, true);
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.g1) {
            setupWithViewPager(null);
            this.g1 = false;
        }
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        j jVar;
        Drawable drawable;
        int i = 0;
        while (true) {
            f fVar = this.d;
            if (i >= fVar.getChildCount()) {
                super.onDraw(canvas);
                return;
            }
            View childAt = fVar.getChildAt(i);
            if ((childAt instanceof j) && (drawable = (jVar = (j) childAt).i) != null) {
                drawable.setBounds(jVar.getLeft(), jVar.getTop(), jVar.getRight(), jVar.getBottom());
                jVar.i.draw(canvas);
            }
            i++;
        }
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setCollectionInfo((AccessibilityNodeInfo.CollectionInfo) Q.C(1, getTabCount(), 1).a);
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        return (getTabMode() == 0 || getTabMode() == 2) && super.onInterceptTouchEvent(motionEvent);
    }

    /* JADX WARN: Removed duplicated region for block: B:36:? A[RETURN, SYNTHETIC] */
    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onMeasure(int r7, int r8) {
        /*
            r6 = this;
            android.content.Context r0 = r6.getContext()
            int r1 = r6.getDefaultHeight()
            float r0 = com.google.android.material.internal.p.g(r0, r1)
            int r0 = java.lang.Math.round(r0)
            int r1 = android.view.View.MeasureSpec.getMode(r8)
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = 0
            r4 = 1073741824(0x40000000, float:2.0)
            r5 = 1
            if (r1 == r2) goto L2e
            if (r1 == 0) goto L1f
            goto L41
        L1f:
            int r8 = r6.getPaddingTop()
            int r8 = r8 + r0
            int r0 = r6.getPaddingBottom()
            int r0 = r0 + r8
            int r8 = android.view.View.MeasureSpec.makeMeasureSpec(r0, r4)
            goto L41
        L2e:
            int r1 = r6.getChildCount()
            if (r1 != r5) goto L41
            int r1 = android.view.View.MeasureSpec.getSize(r8)
            if (r1 < r0) goto L41
            android.view.View r1 = r6.getChildAt(r3)
            r1.setMinimumHeight(r0)
        L41:
            int r0 = android.view.View.MeasureSpec.getSize(r7)
            int r1 = android.view.View.MeasureSpec.getMode(r7)
            if (r1 == 0) goto L5f
            int r1 = r6.w
            if (r1 <= 0) goto L50
            goto L5d
        L50:
            float r0 = (float) r0
            android.content.Context r1 = r6.getContext()
            r2 = 56
            float r1 = com.google.android.material.internal.p.g(r1, r2)
            float r0 = r0 - r1
            int r1 = (int) r0
        L5d:
            r6.u = r1
        L5f:
            super.onMeasure(r7, r8)
            int r7 = r6.getChildCount()
            if (r7 != r5) goto Laa
            android.view.View r7 = r6.getChildAt(r3)
            int r0 = r6.C
            if (r0 == 0) goto L82
            if (r0 == r5) goto L76
            r1 = 2
            if (r0 == r1) goto L82
            goto Laa
        L76:
            int r0 = r7.getMeasuredWidth()
            int r1 = r6.getMeasuredWidth()
            if (r0 == r1) goto L81
            goto L8c
        L81:
            return
        L82:
            int r0 = r7.getMeasuredWidth()
            int r1 = r6.getMeasuredWidth()
            if (r0 >= r1) goto Laa
        L8c:
            int r0 = r6.getPaddingTop()
            int r1 = r6.getPaddingBottom()
            int r1 = r1 + r0
            android.view.ViewGroup$LayoutParams r0 = r7.getLayoutParams()
            int r0 = r0.height
            int r8 = android.view.ViewGroup.getChildMeasureSpec(r8, r1, r0)
            int r0 = r6.getMeasuredWidth()
            int r0 = android.view.View.MeasureSpec.makeMeasureSpec(r0, r4)
            r7.measure(r0, r8)
        Laa:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.tabs.l.onMeasure(int, int):void");
    }

    @Override // android.widget.HorizontalScrollView, android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        if (motionEvent.getActionMasked() != 8 || getTabMode() == 0 || getTabMode() == 2) {
            return super.onTouchEvent(motionEvent);
        }
        return false;
    }

    public final void p(ViewPager viewPager, boolean z) {
        l lVar;
        ArrayList arrayList;
        ArrayList arrayList2;
        ViewPager viewPager2 = this.W;
        if (viewPager2 != null) {
            h hVar = this.e1;
            if (hVar != null && (arrayList2 = viewPager2.e1) != null) {
                arrayList2.remove(hVar);
            }
            c cVar = this.f1;
            if (cVar != null && (arrayList = this.W.g1) != null) {
                arrayList.remove(cVar);
            }
        }
        k kVar = this.M;
        ArrayList arrayList3 = this.L;
        if (kVar != null) {
            arrayList3.remove(kVar);
            this.M = null;
        }
        if (viewPager != null) {
            this.W = viewPager;
            if (this.e1 == null) {
                this.e1 = new h(this);
            }
            h hVar2 = this.e1;
            hVar2.c = 0;
            hVar2.b = 0;
            if (viewPager.e1 == null) {
                viewPager.e1 = new ArrayList();
            }
            viewPager.e1.add(hVar2);
            k kVar2 = new k(viewPager, 0);
            this.M = kVar2;
            if (!arrayList3.contains(kVar2)) {
                arrayList3.add(kVar2);
            }
            androidx.viewpager.widget.a adapter = viewPager.getAdapter();
            if (adapter != null) {
                n(adapter, true);
            }
            if (this.f1 == null) {
                this.f1 = new c(this);
            }
            c cVar2 = this.f1;
            cVar2.a = true;
            if (viewPager.g1 == null) {
                viewPager.g1 = new ArrayList();
            }
            viewPager.g1.add(cVar2);
            o(viewPager.getCurrentItem(), DefinitionKt.NO_Float_VALUE, true, true, true);
            lVar = this;
        } else {
            lVar = this;
            lVar.W = null;
            n(null, false);
        }
        lVar.g1 = z;
    }

    public final void q(boolean z) {
        int i = 0;
        while (true) {
            f fVar = this.d;
            if (i >= fVar.getChildCount()) {
                return;
            }
            View childAt = fVar.getChildAt(i);
            childAt.setMinimumWidth(getTabMinWidth());
            LinearLayout.LayoutParams layoutParams = (LinearLayout.LayoutParams) childAt.getLayoutParams();
            if (this.C == 1 && this.z == 0) {
                layoutParams.width = 0;
                layoutParams.weight = 1.0f;
            } else {
                layoutParams.width = -2;
                layoutParams.weight = DefinitionKt.NO_Float_VALUE;
            }
            if (z) {
                childAt.requestLayout();
            }
            i++;
        }
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        Drawable background = getBackground();
        if (background instanceof com.google.android.material.shape.g) {
            ((com.google.android.material.shape.g) background).l(f);
        }
    }

    public void setInlineLabel(boolean z) {
        if (this.D == z) {
            return;
        }
        this.D = z;
        int i = 0;
        while (true) {
            f fVar = this.d;
            if (i >= fVar.getChildCount()) {
                f();
                return;
            }
            View childAt = fVar.getChildAt(i);
            if (childAt instanceof j) {
                j jVar = (j) childAt;
                jVar.setOrientation(!jVar.k.D ? 1 : 0);
                TextView textView = jVar.g;
                if (textView == null && jVar.h == null) {
                    jVar.h(jVar.b, jVar.c, true);
                } else {
                    jVar.h(textView, jVar.h, false);
                }
            }
            i++;
        }
    }

    public void setInlineLabelResource(int i) {
        setInlineLabel(getResources().getBoolean(i));
    }

    @Deprecated
    public void setOnTabSelectedListener(e eVar) {
        setOnTabSelectedListener((d) eVar);
    }

    public void setScrollAnimatorListener(Animator.AnimatorListener animatorListener) {
        h();
        this.V.addListener(animatorListener);
    }

    public void setSelectedTabIndicator(Drawable drawable) {
        if (drawable == null) {
            drawable = new GradientDrawable();
        }
        Drawable drawableMutate = drawable.mutate();
        this.o = drawableMutate;
        int i = this.p;
        if (i != 0) {
            drawableMutate.setTint(i);
        } else {
            drawableMutate.setTintList(null);
        }
        int intrinsicHeight = this.F;
        if (intrinsicHeight == -1) {
            intrinsicHeight = this.o.getIntrinsicHeight();
        }
        this.d.b(intrinsicHeight);
    }

    public void setSelectedTabIndicatorColor(int i) {
        this.p = i;
        Drawable drawable = this.o;
        if (i != 0) {
            drawable.setTint(i);
        } else {
            drawable.setTintList(null);
        }
        q(false);
    }

    public void setSelectedTabIndicatorGravity(int i) {
        if (this.B != i) {
            this.B = i;
            WeakHashMap weakHashMap = V.a;
            this.d.postInvalidateOnAnimation();
        }
    }

    @Deprecated
    public void setSelectedTabIndicatorHeight(int i) {
        this.F = i;
        this.d.b(i);
    }

    public void setTabGravity(int i) {
        if (this.z != i) {
            this.z = i;
            f();
        }
    }

    public void setTabIconTint(ColorStateList colorStateList) {
        if (this.m != colorStateList) {
            this.m = colorStateList;
            ArrayList arrayList = this.b;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                j jVar = ((g) arrayList.get(i)).h;
                if (jVar != null) {
                    jVar.e();
                }
            }
        }
    }

    public void setTabIconTintResource(int i) {
        setTabIconTint(androidx.core.content.c.c(getContext(), i));
    }

    public void setTabIndicatorAnimationMode(int i) {
        this.G = i;
        if (i == 0) {
            this.I = new com.google.android.material.shape.e(18);
            return;
        }
        if (i == 1) {
            this.I = new a(0);
        } else {
            if (i == 2) {
                this.I = new a(1);
                return;
            }
            throw new IllegalArgumentException(i + " is not a valid TabIndicatorAnimationMode");
        }
    }

    public void setTabIndicatorFullWidth(boolean z) {
        this.E = z;
        int i = f.c;
        f fVar = this.d;
        fVar.a(fVar.b.getSelectedTabPosition());
        WeakHashMap weakHashMap = V.a;
        fVar.postInvalidateOnAnimation();
    }

    public void setTabMode(int i) {
        if (i != this.C) {
            this.C = i;
            f();
        }
    }

    public void setTabRippleColor(ColorStateList colorStateList) {
        if (this.n == colorStateList) {
            return;
        }
        this.n = colorStateList;
        int i = 0;
        while (true) {
            f fVar = this.d;
            if (i >= fVar.getChildCount()) {
                return;
            }
            View childAt = fVar.getChildAt(i);
            if (childAt instanceof j) {
                Context context = getContext();
                int i2 = j.l;
                ((j) childAt).f(context);
            }
            i++;
        }
    }

    public void setTabRippleColorResource(int i) {
        setTabRippleColor(androidx.core.content.c.c(getContext(), i));
    }

    public void setTabTextColors(ColorStateList colorStateList) {
        if (this.l != colorStateList) {
            this.l = colorStateList;
            ArrayList arrayList = this.b;
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                j jVar = ((g) arrayList.get(i)).h;
                if (jVar != null) {
                    jVar.e();
                }
            }
        }
    }

    @Deprecated
    public void setTabsFromPagerAdapter(androidx.viewpager.widget.a aVar) {
        n(aVar, false);
    }

    public void setUnboundedRipple(boolean z) {
        if (this.H == z) {
            return;
        }
        this.H = z;
        int i = 0;
        while (true) {
            f fVar = this.d;
            if (i >= fVar.getChildCount()) {
                return;
            }
            View childAt = fVar.getChildAt(i);
            if (childAt instanceof j) {
                Context context = getContext();
                int i2 = j.l;
                ((j) childAt).f(context);
            }
            i++;
        }
    }

    public void setUnboundedRippleResource(int i) {
        setUnboundedRipple(getResources().getBoolean(i));
    }

    public void setupWithViewPager(ViewPager viewPager) {
        p(viewPager, false);
    }

    @Override // android.widget.HorizontalScrollView, android.widget.FrameLayout, android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return getTabScrollRange() > 0;
    }

    public l(Context context, AttributeSet attributeSet) throws Resources.NotFoundException {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, R.attr.tabStyle, R.style.Widget_Design_TabLayout), attributeSet, R.attr.tabStyle);
        this.a = -1;
        this.b = new ArrayList();
        this.k = -1;
        this.p = 0;
        this.u = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.F = -1;
        this.L = new ArrayList();
        this.i1 = new androidx.constraintlayout.core.d(12);
        Context context2 = getContext();
        setHorizontalScrollBarEnabled(false);
        f fVar = new f(this, context2);
        this.d = fVar;
        super.addView(fVar, 0, new FrameLayout.LayoutParams(-2, -1));
        TypedArray typedArrayL = p.l(context2, attributeSet, com.google.android.material.a.P, R.attr.tabStyle, R.style.Widget_Design_TabLayout, 24);
        ColorStateList colorStateListJ = Y3.j(getBackground());
        if (colorStateListJ != null) {
            com.google.android.material.shape.g gVar = new com.google.android.material.shape.g();
            gVar.m(colorStateListJ);
            gVar.k(context2);
            WeakHashMap weakHashMap = V.a;
            gVar.l(L.e(this));
            setBackground(gVar);
        }
        setSelectedTabIndicator(AbstractC3442d4.c(context2, typedArrayL, 5));
        setSelectedTabIndicatorColor(typedArrayL.getColor(8, 0));
        fVar.b(typedArrayL.getDimensionPixelSize(11, -1));
        setSelectedTabIndicatorGravity(typedArrayL.getInt(10, 0));
        setTabIndicatorAnimationMode(typedArrayL.getInt(7, 0));
        setTabIndicatorFullWidth(typedArrayL.getBoolean(9, true));
        int dimensionPixelSize = typedArrayL.getDimensionPixelSize(16, 0);
        this.h = dimensionPixelSize;
        this.g = dimensionPixelSize;
        this.f = dimensionPixelSize;
        this.e = dimensionPixelSize;
        this.e = typedArrayL.getDimensionPixelSize(19, dimensionPixelSize);
        this.f = typedArrayL.getDimensionPixelSize(20, dimensionPixelSize);
        this.g = typedArrayL.getDimensionPixelSize(18, dimensionPixelSize);
        this.h = typedArrayL.getDimensionPixelSize(17, dimensionPixelSize);
        if (AbstractC3436c4.c(context2, R.attr.isMaterial3Theme, false)) {
            this.i = R.attr.textAppearanceTitleSmall;
        } else {
            this.i = R.attr.textAppearanceButton;
        }
        int resourceId = typedArrayL.getResourceId(24, R.style.TextAppearance_Design_Tab);
        this.j = resourceId;
        int[] iArr = androidx.appcompat.a.y;
        TypedArray typedArrayObtainStyledAttributes = context2.obtainStyledAttributes(resourceId, iArr);
        try {
            float dimensionPixelSize2 = typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
            this.r = dimensionPixelSize2;
            this.l = AbstractC3442d4.a(context2, typedArrayObtainStyledAttributes, 3);
            typedArrayObtainStyledAttributes.recycle();
            if (typedArrayL.hasValue(22)) {
                this.k = typedArrayL.getResourceId(22, resourceId);
            }
            int i = this.k;
            int[] iArr2 = HorizontalScrollView.EMPTY_STATE_SET;
            int[] iArr3 = HorizontalScrollView.SELECTED_STATE_SET;
            if (i != -1) {
                typedArrayObtainStyledAttributes = context2.obtainStyledAttributes(i, iArr);
                try {
                    typedArrayObtainStyledAttributes.getDimensionPixelSize(0, (int) dimensionPixelSize2);
                    ColorStateList colorStateListA = AbstractC3442d4.a(context2, typedArrayObtainStyledAttributes, 3);
                    if (colorStateListA != null) {
                        this.l = new ColorStateList(new int[][]{iArr3, iArr2}, new int[]{colorStateListA.getColorForState(new int[]{android.R.attr.state_selected}, colorStateListA.getDefaultColor()), this.l.getDefaultColor()});
                    }
                } finally {
                }
            }
            if (typedArrayL.hasValue(25)) {
                this.l = AbstractC3442d4.a(context2, typedArrayL, 25);
            }
            if (typedArrayL.hasValue(23)) {
                this.l = new ColorStateList(new int[][]{iArr3, iArr2}, new int[]{typedArrayL.getColor(23, 0), this.l.getDefaultColor()});
            }
            this.m = AbstractC3442d4.a(context2, typedArrayL, 3);
            this.q = p.m(typedArrayL.getInt(4, -1), null);
            this.n = AbstractC3442d4.a(context2, typedArrayL, 21);
            this.A = typedArrayL.getInt(6, 300);
            this.J = AbstractC3430b4.e(context2, R.attr.motionEasingEmphasizedInterpolator, com.google.android.material.animation.a.b);
            this.v = typedArrayL.getDimensionPixelSize(14, -1);
            this.w = typedArrayL.getDimensionPixelSize(13, -1);
            this.t = typedArrayL.getResourceId(0, 0);
            this.y = typedArrayL.getDimensionPixelSize(1, 0);
            this.C = typedArrayL.getInt(15, 1);
            this.z = typedArrayL.getInt(2, 0);
            this.D = typedArrayL.getBoolean(12, false);
            this.H = typedArrayL.getBoolean(26, false);
            typedArrayL.recycle();
            Resources resources = getResources();
            this.s = resources.getDimensionPixelSize(R.dimen.design_tab_text_size_2line);
            this.x = resources.getDimensionPixelSize(R.dimen.design_tab_scrollable_min_width);
            f();
        } finally {
        }
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
    public final void addView(View view, int i) {
        d(view);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup
    public final FrameLayout.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return generateDefaultLayoutParams();
    }

    @Deprecated
    public void setOnTabSelectedListener(d dVar) {
        d dVar2 = this.K;
        ArrayList arrayList = this.L;
        if (dVar2 != null) {
            arrayList.remove(dVar2);
        }
        this.K = dVar;
        if (dVar == null || arrayList.contains(dVar)) {
            return;
        }
        arrayList.add(dVar);
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup, android.view.ViewManager
    public final void addView(View view, ViewGroup.LayoutParams layoutParams) {
        d(view);
    }

    @Override // android.widget.HorizontalScrollView, android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        d(view);
    }

    public void setSelectedTabIndicator(int i) {
        if (i != 0) {
            setSelectedTabIndicator(com.facebook.appevents.g.f(getContext(), i));
        } else {
            setSelectedTabIndicator((Drawable) null);
        }
    }
}
