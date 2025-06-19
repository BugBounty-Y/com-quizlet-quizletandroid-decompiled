package androidx.viewpager.widget;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.widget.EdgeEffect;
import android.widget.Scroller;
import androidx.annotation.NonNull;
import androidx.appcompat.app.J;
import androidx.appcompat.widget.D0;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.customview.view.AbsSavedState;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.p0;
import com.comscore.streaming.ContentType;
import com.google.android.material.tabs.h;
import com.google.android.material.tabs.l;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Collections;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public class ViewPager extends ViewGroup {
    public static final int[] j1 = {R.attr.layout_gravity};
    public static final androidx.constraintlayout.core.e k1 = new androidx.constraintlayout.core.e(3);
    public static final androidx.customview.widget.c l1 = new androidx.customview.widget.c(1);
    public int A;
    public int B;
    public float C;
    public float D;
    public float E;
    public float F;
    public int G;
    public VelocityTracker H;
    public int I;
    public int J;
    public int K;
    public int L;
    public EdgeEffect M;
    public EdgeEffect V;
    public boolean W;
    public int a;
    public final ArrayList b;
    public final c c;
    public boolean c1;
    public final Rect d;
    public int d1;
    public a e;
    public ArrayList e1;
    public int f;
    public f f1;
    public int g;
    public ArrayList g1;
    public Parcelable h;
    public final J h1;
    public ClassLoader i;
    public int i1;
    public Scroller j;
    public boolean k;
    public D0 l;
    public int m;
    public Drawable n;
    public int o;
    public int p;
    public float q;
    public float r;
    public int s;
    public boolean t;
    public boolean u;
    public boolean v;
    public int w;
    public boolean x;
    public boolean y;
    public int z;

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new g();
        public int c;
        public Parcelable d;
        public final ClassLoader e;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            classLoader = classLoader == null ? getClass().getClassLoader() : classLoader;
            this.c = parcel.readInt();
            this.d = parcel.readParcelable(classLoader);
            this.e = classLoader;
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("FragmentPager.SavedState{");
            sb.append(Integer.toHexString(System.identityHashCode(this)));
            sb.append(" position=");
            return android.support.v4.media.session.a.r(sb, this.c, "}");
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.c);
            parcel.writeParcelable(this.d, i);
        }
    }

    public ViewPager(@NonNull Context context) {
        super(context);
        this.b = new ArrayList();
        this.c = new c();
        this.d = new Rect();
        this.g = -1;
        this.h = null;
        this.i = null;
        this.q = -3.4028235E38f;
        this.r = Float.MAX_VALUE;
        this.w = 1;
        this.G = -1;
        this.W = true;
        this.h1 = new J(this, 13);
        this.i1 = 0;
        k();
    }

    public static boolean c(int i, int i2, int i3, View view, boolean z) {
        int i4;
        if (!(view instanceof ViewGroup)) {
            return z ? false : false;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int scrollX = view.getScrollX();
        int scrollY = view.getScrollY();
        for (int childCount = viewGroup.getChildCount() - 1; childCount >= 0; childCount--) {
            View childAt = viewGroup.getChildAt(childCount);
            int i5 = i2 + scrollX;
            if (i5 >= childAt.getLeft() && i5 < childAt.getRight() && (i4 = i3 + scrollY) >= childAt.getTop() && i4 < childAt.getBottom() && c(i, i5 - childAt.getLeft(), i4 - childAt.getTop(), childAt, true)) {
                break;
            }
        }
        if (z || !view.canScrollHorizontally(-i)) {
        }
        return true;
    }

    private int getClientWidth() {
        return (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
    }

    private void setScrollingCacheEnabled(boolean z) {
        if (this.u != z) {
            this.u = z;
        }
    }

    public final c a(int i, int i2) {
        c cVar = new c();
        cVar.b = i;
        cVar.a = this.e.f(this, i);
        this.e.getClass();
        cVar.d = 1.0f;
        ArrayList arrayList = this.b;
        if (i2 < 0 || i2 >= arrayList.size()) {
            arrayList.add(cVar);
            return cVar;
        }
        arrayList.add(i2, cVar);
        return cVar;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void addFocusables(ArrayList arrayList, int i, int i2) {
        c cVarH;
        int size = arrayList.size();
        int descendantFocusability = getDescendantFocusability();
        if (descendantFocusability != 393216) {
            for (int i3 = 0; i3 < getChildCount(); i3++) {
                View childAt = getChildAt(i3);
                if (childAt.getVisibility() == 0 && (cVarH = h(childAt)) != null && cVarH.b == this.f) {
                    childAt.addFocusables(arrayList, i, i2);
                }
            }
        }
        if ((descendantFocusability != 262144 || size == arrayList.size()) && isFocusable()) {
            if ((i2 & 1) == 1 && isInTouchMode() && !isFocusableInTouchMode()) {
                return;
            }
            arrayList.add(this);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void addTouchables(ArrayList arrayList) {
        c cVarH;
        for (int i = 0; i < getChildCount(); i++) {
            View childAt = getChildAt(i);
            if (childAt.getVisibility() == 0 && (cVarH = h(childAt)) != null && cVarH.b == this.f) {
                childAt.addTouchables(arrayList);
            }
        }
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        if (!checkLayoutParams(layoutParams)) {
            layoutParams = generateDefaultLayoutParams();
        }
        d dVar = (d) layoutParams;
        boolean z = dVar.a | (view.getClass().getAnnotation(b.class) != null);
        dVar.a = z;
        if (!this.t) {
            super.addView(view, i, layoutParams);
        } else {
            if (z) {
                throw new IllegalStateException("Cannot add pager decor view during layout");
            }
            dVar.d = true;
            addViewInLayout(view, i, layoutParams);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x00cd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(int r8) throws android.content.res.Resources.NotFoundException {
        /*
            r7 = this;
            android.view.View r0 = r7.findFocus()
            r1 = 0
            if (r0 != r7) goto L9
        L7:
            r0 = r1
            goto L60
        L9:
            if (r0 == 0) goto L60
            android.view.ViewParent r2 = r0.getParent()
        Lf:
            boolean r3 = r2 instanceof android.view.ViewGroup
            if (r3 == 0) goto L1b
            if (r2 != r7) goto L16
            goto L60
        L16:
            android.view.ViewParent r2 = r2.getParent()
            goto Lf
        L1b:
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            r2.<init>()
            java.lang.Class r3 = r0.getClass()
            java.lang.String r3 = r3.getSimpleName()
            r2.append(r3)
            android.view.ViewParent r0 = r0.getParent()
        L2f:
            boolean r3 = r0 instanceof android.view.ViewGroup
            if (r3 == 0) goto L48
            java.lang.String r3 = " => "
            r2.append(r3)
            java.lang.Class r3 = r0.getClass()
            java.lang.String r3 = r3.getSimpleName()
            r2.append(r3)
            android.view.ViewParent r0 = r0.getParent()
            goto L2f
        L48:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r3 = "arrowScroll tried to find focus based on non-child current focused view "
            r0.<init>(r3)
            java.lang.String r2 = r2.toString()
            r0.append(r2)
            java.lang.String r0 = r0.toString()
            java.lang.String r2 = "ViewPager"
            android.util.Log.e(r2, r0)
            goto L7
        L60:
            android.view.FocusFinder r1 = android.view.FocusFinder.getInstance()
            android.view.View r1 = r1.findNextFocus(r7, r0, r8)
            r2 = 1
            r3 = 0
            r4 = 66
            r5 = 17
            if (r1 == 0) goto Lb3
            if (r1 == r0) goto Lb3
            android.graphics.Rect r6 = r7.d
            if (r8 != r5) goto L97
            android.graphics.Rect r4 = r7.g(r6, r1)
            int r4 = r4.left
            android.graphics.Rect r5 = r7.g(r6, r0)
            int r5 = r5.left
            if (r0 == 0) goto L91
            if (r4 < r5) goto L91
            int r0 = r7.f
            if (r0 <= 0) goto Lcd
            int r0 = r0 - r2
            r7.v = r3
            r7.v(r0, r3, r2, r3)
            goto Lce
        L91:
            boolean r0 = r1.requestFocus()
        L95:
            r3 = r0
            goto Lcf
        L97:
            if (r8 != r4) goto Lcf
            android.graphics.Rect r2 = r7.g(r6, r1)
            int r2 = r2.left
            android.graphics.Rect r3 = r7.g(r6, r0)
            int r3 = r3.left
            if (r0 == 0) goto Lae
            if (r2 > r3) goto Lae
            boolean r0 = r7.n()
            goto L95
        Lae:
            boolean r0 = r1.requestFocus()
            goto L95
        Lb3:
            if (r8 == r5) goto Lc2
            if (r8 != r2) goto Lb8
            goto Lc2
        Lb8:
            if (r8 == r4) goto Lbd
            r0 = 2
            if (r8 != r0) goto Lcf
        Lbd:
            boolean r3 = r7.n()
            goto Lcf
        Lc2:
            int r0 = r7.f
            if (r0 <= 0) goto Lcd
            int r0 = r0 - r2
            r7.v = r3
            r7.v(r0, r3, r2, r3)
            goto Lce
        Lcd:
            r2 = r3
        Lce:
            r3 = r2
        Lcf:
            if (r3 == 0) goto Ld8
            int r8 = android.view.SoundEffectConstants.getContantForFocusDirection(r8)
            r7.playSoundEffect(r8)
        Ld8:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.b(int):boolean");
    }

    @Override // android.view.View
    public final boolean canScrollHorizontally(int i) {
        if (this.e == null) {
            return false;
        }
        int clientWidth = getClientWidth();
        int scrollX = getScrollX();
        return i < 0 ? scrollX > ((int) (((float) clientWidth) * this.q)) : i > 0 && scrollX < ((int) (((float) clientWidth) * this.r));
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return (layoutParams instanceof d) && super.checkLayoutParams(layoutParams);
    }

    @Override // android.view.View
    public final void computeScroll() {
        this.k = true;
        if (this.j.isFinished() || !this.j.computeScrollOffset()) {
            d(true);
            return;
        }
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        int currX = this.j.getCurrX();
        int currY = this.j.getCurrY();
        if (scrollX != currX || scrollY != currY) {
            scrollTo(currX, currY);
            if (!o(currX)) {
                this.j.abortAnimation();
                scrollTo(0, currY);
            }
        }
        WeakHashMap weakHashMap = V.a;
        postInvalidateOnAnimation();
    }

    public final void d(boolean z) {
        boolean z2 = this.i1 == 2;
        if (z2) {
            setScrollingCacheEnabled(false);
            if (!this.j.isFinished()) {
                this.j.abortAnimation();
                int scrollX = getScrollX();
                int scrollY = getScrollY();
                int currX = this.j.getCurrX();
                int currY = this.j.getCurrY();
                if (scrollX != currX || scrollY != currY) {
                    scrollTo(currX, currY);
                    if (currX != scrollX) {
                        o(currX);
                    }
                }
            }
        }
        this.v = false;
        int i = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                break;
            }
            c cVar = (c) arrayList.get(i);
            if (cVar.c) {
                cVar.c = false;
                z2 = true;
            }
            i++;
        }
        if (z2) {
            J j = this.h1;
            if (!z) {
                j.run();
            } else {
                WeakHashMap weakHashMap = V.a;
                postOnAnimation(j);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0065 A[RETURN] */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean dispatchKeyEvent(android.view.KeyEvent r6) throws android.content.res.Resources.NotFoundException {
        /*
            r5 = this;
            boolean r0 = super.dispatchKeyEvent(r6)
            r1 = 1
            if (r0 != 0) goto L66
            int r0 = r6.getAction()
            r2 = 0
            if (r0 != 0) goto L61
            int r0 = r6.getKeyCode()
            r3 = 21
            r4 = 2
            if (r0 == r3) goto L48
            r3 = 22
            if (r0 == r3) goto L36
            r3 = 61
            if (r0 == r3) goto L20
            goto L61
        L20:
            boolean r0 = r6.hasNoModifiers()
            if (r0 == 0) goto L2b
            boolean r6 = r5.b(r4)
            goto L62
        L2b:
            boolean r6 = r6.hasModifiers(r1)
            if (r6 == 0) goto L61
            boolean r6 = r5.b(r1)
            goto L62
        L36:
            boolean r6 = r6.hasModifiers(r4)
            if (r6 == 0) goto L41
            boolean r6 = r5.n()
            goto L62
        L41:
            r6 = 66
            boolean r6 = r5.b(r6)
            goto L62
        L48:
            boolean r6 = r6.hasModifiers(r4)
            if (r6 == 0) goto L5a
            int r6 = r5.f
            if (r6 <= 0) goto L61
            int r6 = r6 - r1
            r5.v = r2
            r5.v(r6, r2, r1, r2)
            r6 = r1
            goto L62
        L5a:
            r6 = 17
            boolean r6 = r5.b(r6)
            goto L62
        L61:
            r6 = r2
        L62:
            if (r6 == 0) goto L65
            goto L66
        L65:
            return r2
        L66:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.dispatchKeyEvent(android.view.KeyEvent):boolean");
    }

    @Override // android.view.View
    public final boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        c cVarH;
        if (accessibilityEvent.getEventType() == 4096) {
            return super.dispatchPopulateAccessibilityEvent(accessibilityEvent);
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (childAt.getVisibility() == 0 && (cVarH = h(childAt)) != null && cVarH.b == this.f && childAt.dispatchPopulateAccessibilityEvent(accessibilityEvent)) {
                return true;
            }
        }
        return false;
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        a aVar;
        super.draw(canvas);
        int overScrollMode = getOverScrollMode();
        boolean zDraw = false;
        if (overScrollMode == 0 || (overScrollMode == 1 && (aVar = this.e) != null && aVar.c() > 1)) {
            if (!this.M.isFinished()) {
                int iSave = canvas.save();
                int height = (getHeight() - getPaddingTop()) - getPaddingBottom();
                int width = getWidth();
                canvas.rotate(270.0f);
                canvas.translate(getPaddingTop() + (-height), this.q * width);
                this.M.setSize(height, width);
                zDraw = this.M.draw(canvas);
                canvas.restoreToCount(iSave);
            }
            if (!this.V.isFinished()) {
                int iSave2 = canvas.save();
                int width2 = getWidth();
                int height2 = (getHeight() - getPaddingTop()) - getPaddingBottom();
                canvas.rotate(90.0f);
                canvas.translate(-getPaddingTop(), (-(this.r + 1.0f)) * width2);
                this.V.setSize(height2, width2);
                zDraw |= this.V.draw(canvas);
                canvas.restoreToCount(iSave2);
            }
        } else {
            this.M.finish();
            this.V.finish();
        }
        if (zDraw) {
            WeakHashMap weakHashMap = V.a;
            postInvalidateOnAnimation();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void drawableStateChanged() {
        super.drawableStateChanged();
        Drawable drawable = this.n;
        if (drawable == null || !drawable.isStateful()) {
            return;
        }
        drawable.setState(getDrawableState());
    }

    public final void e() {
        int iC = this.e.c();
        this.a = iC;
        ArrayList arrayList = this.b;
        boolean z = arrayList.size() < (this.w * 2) + 1 && arrayList.size() < iC;
        int iMax = this.f;
        int i = 0;
        boolean z2 = false;
        while (i < arrayList.size()) {
            c cVar = (c) arrayList.get(i);
            int iD = this.e.d(cVar.a);
            if (iD != -1) {
                if (iD == -2) {
                    arrayList.remove(i);
                    i--;
                    if (!z2) {
                        this.e.i(this);
                        z2 = true;
                    }
                    this.e.a(this, cVar.b, cVar.a);
                    int i2 = this.f;
                    if (i2 == cVar.b) {
                        iMax = Math.max(0, Math.min(i2, iC - 1));
                    }
                } else {
                    int i3 = cVar.b;
                    if (i3 != iD) {
                        if (i3 == this.f) {
                            iMax = iD;
                        }
                        cVar.b = iD;
                    }
                }
                z = true;
            }
            i++;
        }
        if (z2) {
            this.e.b();
        }
        Collections.sort(arrayList, k1);
        if (z) {
            int childCount = getChildCount();
            for (int i4 = 0; i4 < childCount; i4++) {
                d dVar = (d) getChildAt(i4).getLayoutParams();
                if (!dVar.a) {
                    dVar.c = DefinitionKt.NO_Float_VALUE;
                }
            }
            v(iMax, 0, false, true);
            requestLayout();
        }
    }

    public final void f(int i) {
        f fVar = this.f1;
        if (fVar != null) {
            ((h) fVar).b(i);
        }
        ArrayList arrayList = this.e1;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i2 = 0; i2 < size; i2++) {
                f fVar2 = (f) this.e1.get(i2);
                if (fVar2 != null) {
                    ((h) fVar2).b(i);
                }
            }
        }
    }

    public final Rect g(Rect rect, View view) {
        if (rect == null) {
            rect = new Rect();
        }
        if (view == null) {
            rect.set(0, 0, 0, 0);
            return rect;
        }
        rect.left = view.getLeft();
        rect.right = view.getRight();
        rect.top = view.getTop();
        rect.bottom = view.getBottom();
        ViewParent parent = view.getParent();
        while ((parent instanceof ViewGroup) && parent != this) {
            ViewGroup viewGroup = (ViewGroup) parent;
            rect.left = viewGroup.getLeft() + rect.left;
            rect.right = viewGroup.getRight() + rect.right;
            rect.top = viewGroup.getTop() + rect.top;
            rect.bottom = viewGroup.getBottom() + rect.bottom;
            parent = viewGroup.getParent();
        }
        return rect;
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        d dVar = new d(-1, -1);
        dVar.c = DefinitionKt.NO_Float_VALUE;
        return dVar;
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return generateDefaultLayoutParams();
    }

    public a getAdapter() {
        return this.e;
    }

    @Override // android.view.ViewGroup
    public final int getChildDrawingOrder(int i, int i2) {
        throw null;
    }

    public int getCurrentItem() {
        return this.f;
    }

    public int getOffscreenPageLimit() {
        return this.w;
    }

    public int getPageMargin() {
        return this.m;
    }

    public final c h(View view) {
        int i = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i >= arrayList.size()) {
                return null;
            }
            c cVar = (c) arrayList.get(i);
            a aVar = this.e;
            Object obj = cVar.a;
            ((p0) aVar).getClass();
            if (((Fragment) obj).getView() == view) {
                return cVar;
            }
            i++;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:29:0x0072, code lost:
    
        return r7;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final androidx.viewpager.widget.c i() {
        /*
            r13 = this;
            int r0 = r13.getClientWidth()
            r1 = 0
            if (r0 <= 0) goto Lf
            int r2 = r13.getScrollX()
            float r2 = (float) r2
            float r3 = (float) r0
            float r2 = r2 / r3
            goto L10
        Lf:
            r2 = r1
        L10:
            if (r0 <= 0) goto L18
            int r3 = r13.m
            float r3 = (float) r3
            float r0 = (float) r0
            float r3 = r3 / r0
            goto L19
        L18:
            r3 = r1
        L19:
            r0 = 0
            r4 = -1
            r5 = 1
            r6 = 0
            r8 = r0
            r9 = r5
            r7 = r6
            r6 = r4
            r4 = r1
        L22:
            java.util.ArrayList r10 = r13.b
            int r11 = r10.size()
            if (r8 >= r11) goto L72
            java.lang.Object r11 = r10.get(r8)
            androidx.viewpager.widget.c r11 = (androidx.viewpager.widget.c) r11
            if (r9 != 0) goto L4c
            int r12 = r11.b
            int r6 = r6 + r5
            if (r12 == r6) goto L4c
            float r1 = r1 + r4
            float r1 = r1 + r3
            androidx.viewpager.widget.c r4 = r13.c
            r4.e = r1
            r4.b = r6
            androidx.viewpager.widget.a r1 = r13.e
            r1.getClass()
            r1 = 1065353216(0x3f800000, float:1.0)
            r4.d = r1
            int r8 = r8 + (-1)
            r6 = r4
            goto L4d
        L4c:
            r6 = r11
        L4d:
            float r1 = r6.e
            float r4 = r6.d
            float r4 = r4 + r1
            float r4 = r4 + r3
            if (r9 != 0) goto L59
            int r9 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
            if (r9 < 0) goto L72
        L59:
            int r4 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r4 < 0) goto L71
            int r4 = r10.size()
            int r4 = r4 - r5
            if (r8 != r4) goto L65
            goto L71
        L65:
            int r4 = r6.b
            float r7 = r6.d
            int r8 = r8 + 1
            r9 = r6
            r6 = r4
            r4 = r7
            r7 = r9
            r9 = r0
            goto L22
        L71:
            return r6
        L72:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.i():androidx.viewpager.widget.c");
    }

    public final c j(int i) {
        int i2 = 0;
        while (true) {
            ArrayList arrayList = this.b;
            if (i2 >= arrayList.size()) {
                return null;
            }
            c cVar = (c) arrayList.get(i2);
            if (cVar.b == i) {
                return cVar;
            }
            i2++;
        }
    }

    public final void k() {
        setWillNotDraw(false);
        setDescendantFocusability(262144);
        setFocusable(true);
        Context context = getContext();
        this.j = new Scroller(context, l1);
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        float f = context.getResources().getDisplayMetrics().density;
        this.B = viewConfiguration.getScaledPagingTouchSlop();
        this.I = (int) (400.0f * f);
        this.J = viewConfiguration.getScaledMaximumFlingVelocity();
        this.M = new EdgeEffect(context);
        this.V = new EdgeEffect(context);
        this.K = (int) (25.0f * f);
        this.L = (int) (2.0f * f);
        this.z = (int) (f * 16.0f);
        V.o(this, new e(this, 0));
        if (getImportantForAccessibility() == 0) {
            setImportantForAccessibility(1);
        }
        L.m(this, new com.quizlet.data.repository.widget.b(this));
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0065  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(int r12, float r13, int r14) {
        /*
            r11 = this;
            int r14 = r11.d1
            r0 = 0
            r1 = 1
            if (r14 <= 0) goto L6c
            int r14 = r11.getScrollX()
            int r2 = r11.getPaddingLeft()
            int r3 = r11.getPaddingRight()
            int r4 = r11.getWidth()
            int r5 = r11.getChildCount()
            r6 = r0
        L1b:
            if (r6 >= r5) goto L6c
            android.view.View r7 = r11.getChildAt(r6)
            android.view.ViewGroup$LayoutParams r8 = r7.getLayoutParams()
            androidx.viewpager.widget.d r8 = (androidx.viewpager.widget.d) r8
            boolean r9 = r8.a
            if (r9 != 0) goto L2c
            goto L69
        L2c:
            int r8 = r8.b
            r8 = r8 & 7
            if (r8 == r1) goto L50
            r9 = 3
            if (r8 == r9) goto L4a
            r9 = 5
            if (r8 == r9) goto L3a
            r8 = r2
            goto L5d
        L3a:
            int r8 = r4 - r3
            int r9 = r7.getMeasuredWidth()
            int r8 = r8 - r9
            int r9 = r7.getMeasuredWidth()
            int r3 = r3 + r9
        L46:
            r10 = r8
            r8 = r2
            r2 = r10
            goto L5d
        L4a:
            int r8 = r7.getWidth()
            int r8 = r8 + r2
            goto L5d
        L50:
            int r8 = r7.getMeasuredWidth()
            int r8 = r4 - r8
            int r8 = r8 / 2
            int r8 = java.lang.Math.max(r8, r2)
            goto L46
        L5d:
            int r2 = r2 + r14
            int r9 = r7.getLeft()
            int r2 = r2 - r9
            if (r2 == 0) goto L68
            r7.offsetLeftAndRight(r2)
        L68:
            r2 = r8
        L69:
            int r6 = r6 + 1
            goto L1b
        L6c:
            androidx.viewpager.widget.f r14 = r11.f1
            if (r14 == 0) goto L75
            com.google.android.material.tabs.h r14 = (com.google.android.material.tabs.h) r14
            r14.a(r13, r12)
        L75:
            java.util.ArrayList r14 = r11.e1
            if (r14 == 0) goto L91
            int r14 = r14.size()
        L7d:
            if (r0 >= r14) goto L91
            java.util.ArrayList r2 = r11.e1
            java.lang.Object r2 = r2.get(r0)
            androidx.viewpager.widget.f r2 = (androidx.viewpager.widget.f) r2
            if (r2 == 0) goto L8e
            com.google.android.material.tabs.h r2 = (com.google.android.material.tabs.h) r2
            r2.a(r13, r12)
        L8e:
            int r0 = r0 + 1
            goto L7d
        L91:
            r11.c1 = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.l(int, float, int):void");
    }

    public final void m(MotionEvent motionEvent) {
        int actionIndex = motionEvent.getActionIndex();
        if (motionEvent.getPointerId(actionIndex) == this.G) {
            int i = actionIndex == 0 ? 1 : 0;
            this.C = motionEvent.getX(i);
            this.G = motionEvent.getPointerId(i);
            VelocityTracker velocityTracker = this.H;
            if (velocityTracker != null) {
                velocityTracker.clear();
            }
        }
    }

    public final boolean n() throws Resources.NotFoundException {
        a aVar = this.e;
        if (aVar == null || this.f >= aVar.c() - 1) {
            return false;
        }
        int i = this.f + 1;
        this.v = false;
        v(i, 0, true, false);
        return true;
    }

    public final boolean o(int i) {
        if (this.b.size() == 0) {
            if (!this.W) {
                this.c1 = false;
                l(0, DefinitionKt.NO_Float_VALUE, 0);
                if (!this.c1) {
                    throw new IllegalStateException("onPageScrolled did not call superclass implementation");
                }
            }
            return false;
        }
        c cVarI = i();
        int clientWidth = getClientWidth();
        int i2 = this.m;
        int i3 = clientWidth + i2;
        float f = clientWidth;
        int i4 = cVarI.b;
        float f2 = ((i / f) - cVarI.e) / (cVarI.d + (i2 / f));
        this.c1 = false;
        l(i4, f2, (int) (i3 * f2));
        if (this.c1) {
            return true;
        }
        throw new IllegalStateException("onPageScrolled did not call superclass implementation");
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.W = true;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        removeCallbacks(this.h1);
        Scroller scroller = this.j;
        if (scroller != null && !scroller.isFinished()) {
            this.j.abortAnimation();
        }
        super.onDetachedFromWindow();
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        int i;
        float f;
        ArrayList arrayList;
        int i2;
        super.onDraw(canvas);
        if (this.m <= 0 || this.n == null) {
            return;
        }
        ArrayList arrayList2 = this.b;
        if (arrayList2.size() <= 0 || this.e == null) {
            return;
        }
        int scrollX = getScrollX();
        float width = getWidth();
        float f2 = this.m / width;
        int i3 = 0;
        c cVar = (c) arrayList2.get(0);
        float f3 = cVar.e;
        int size = arrayList2.size();
        int i4 = cVar.b;
        int i5 = ((c) arrayList2.get(size - 1)).b;
        while (i4 < i5) {
            while (true) {
                i = cVar.b;
                if (i4 <= i || i3 >= size) {
                    break;
                }
                i3++;
                cVar = (c) arrayList2.get(i3);
            }
            if (i4 == i) {
                float f4 = cVar.e;
                float f5 = cVar.d;
                f = (f4 + f5) * width;
                f3 = f4 + f5 + f2;
            } else {
                this.e.getClass();
                f = (f3 + 1.0f) * width;
                f3 = 1.0f + f2 + f3;
            }
            if (this.m + f > scrollX) {
                arrayList = arrayList2;
                i2 = scrollX;
                this.n.setBounds(Math.round(f), this.o, Math.round(this.m + f), this.p);
                this.n.draw(canvas);
            } else {
                arrayList = arrayList2;
                i2 = scrollX;
            }
            if (f > i2 + r3) {
                return;
            }
            i4++;
            arrayList2 = arrayList;
            scrollX = i2;
        }
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction() & 255;
        if (action == 3 || action == 1) {
            t();
            return false;
        }
        if (action != 0) {
            if (this.x) {
                return true;
            }
            if (this.y) {
                return false;
            }
        }
        if (action == 0) {
            float x = motionEvent.getX();
            this.E = x;
            this.C = x;
            float y = motionEvent.getY();
            this.F = y;
            this.D = y;
            this.G = motionEvent.getPointerId(0);
            this.y = false;
            this.k = true;
            this.j.computeScrollOffset();
            if (this.i1 != 2 || Math.abs(this.j.getFinalX() - this.j.getCurrX()) <= this.L) {
                d(false);
                this.x = false;
            } else {
                this.j.abortAnimation();
                this.v = false;
                q();
                this.x = true;
                ViewParent parent = getParent();
                if (parent != null) {
                    parent.requestDisallowInterceptTouchEvent(true);
                }
                setScrollState(1);
            }
        } else if (action == 2) {
            int i = this.G;
            if (i != -1) {
                int iFindPointerIndex = motionEvent.findPointerIndex(i);
                float x2 = motionEvent.getX(iFindPointerIndex);
                float f = x2 - this.C;
                float fAbs = Math.abs(f);
                float y2 = motionEvent.getY(iFindPointerIndex);
                float fAbs2 = Math.abs(y2 - this.F);
                if (f != DefinitionKt.NO_Float_VALUE) {
                    float f2 = this.C;
                    if ((f2 >= this.A || f <= DefinitionKt.NO_Float_VALUE) && ((f2 <= getWidth() - this.A || f >= DefinitionKt.NO_Float_VALUE) && c((int) f, (int) x2, (int) y2, this, false))) {
                        this.C = x2;
                        this.D = y2;
                        this.y = true;
                        return false;
                    }
                }
                float f3 = this.B;
                if (fAbs > f3 && fAbs * 0.5f > fAbs2) {
                    this.x = true;
                    ViewParent parent2 = getParent();
                    if (parent2 != null) {
                        parent2.requestDisallowInterceptTouchEvent(true);
                    }
                    setScrollState(1);
                    float f4 = this.E;
                    float f5 = this.B;
                    this.C = f > DefinitionKt.NO_Float_VALUE ? f4 + f5 : f4 - f5;
                    this.D = y2;
                    setScrollingCacheEnabled(true);
                } else if (fAbs2 > f3) {
                    this.y = true;
                }
                if (this.x && p(x2)) {
                    WeakHashMap weakHashMap = V.a;
                    postInvalidateOnAnimation();
                }
            }
        } else if (action == 6) {
            m(motionEvent);
        }
        if (this.H == null) {
            this.H = VelocityTracker.obtain();
        }
        this.H.addMovement(motionEvent);
        return this.x;
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0094  */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onLayout(boolean r19, int r20, int r21, int r22, int r23) {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.onLayout(boolean, int, int, int, int):void");
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        d dVar;
        d dVar2;
        int i3;
        setMeasuredDimension(View.getDefaultSize(0, i), View.getDefaultSize(0, i2));
        int measuredWidth = getMeasuredWidth();
        this.A = Math.min(measuredWidth / 10, this.z);
        int paddingLeft = (measuredWidth - getPaddingLeft()) - getPaddingRight();
        int measuredHeight = (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom();
        int childCount = getChildCount();
        int i4 = 0;
        while (true) {
            boolean z = true;
            int i5 = 1073741824;
            if (i4 >= childCount) {
                break;
            }
            View childAt = getChildAt(i4);
            if (childAt.getVisibility() != 8 && (dVar2 = (d) childAt.getLayoutParams()) != null && dVar2.a) {
                int i6 = dVar2.b;
                int i7 = i6 & 7;
                int i8 = i6 & ContentType.LONG_FORM_ON_DEMAND;
                boolean z2 = i8 == 48 || i8 == 80;
                if (i7 != 3 && i7 != 5) {
                    z = false;
                }
                int i9 = Integer.MIN_VALUE;
                if (z2) {
                    i3 = Integer.MIN_VALUE;
                    i9 = 1073741824;
                } else {
                    i3 = z ? 1073741824 : Integer.MIN_VALUE;
                }
                int i10 = ((ViewGroup.LayoutParams) dVar2).width;
                if (i10 != -2) {
                    if (i10 == -1) {
                        i10 = paddingLeft;
                    }
                    i9 = 1073741824;
                } else {
                    i10 = paddingLeft;
                }
                int i11 = ((ViewGroup.LayoutParams) dVar2).height;
                if (i11 == -2) {
                    i11 = measuredHeight;
                    i5 = i3;
                } else if (i11 == -1) {
                    i11 = measuredHeight;
                }
                childAt.measure(View.MeasureSpec.makeMeasureSpec(i10, i9), View.MeasureSpec.makeMeasureSpec(i11, i5));
                if (z2) {
                    measuredHeight -= childAt.getMeasuredHeight();
                } else if (z) {
                    paddingLeft -= childAt.getMeasuredWidth();
                }
            }
            i4++;
        }
        View.MeasureSpec.makeMeasureSpec(paddingLeft, 1073741824);
        this.s = View.MeasureSpec.makeMeasureSpec(measuredHeight, 1073741824);
        this.t = true;
        q();
        this.t = false;
        int childCount2 = getChildCount();
        for (int i12 = 0; i12 < childCount2; i12++) {
            View childAt2 = getChildAt(i12);
            if (childAt2.getVisibility() != 8 && ((dVar = (d) childAt2.getLayoutParams()) == null || !dVar.a)) {
                childAt2.measure(View.MeasureSpec.makeMeasureSpec((int) (paddingLeft * dVar.c), 1073741824), this.s);
            }
        }
    }

    @Override // android.view.ViewGroup
    public final boolean onRequestFocusInDescendants(int i, Rect rect) {
        int i2;
        int i3;
        int i4;
        c cVarH;
        int childCount = getChildCount();
        if ((i & 2) != 0) {
            i3 = childCount;
            i2 = 0;
            i4 = 1;
        } else {
            i2 = childCount - 1;
            i3 = -1;
            i4 = -1;
        }
        while (i2 != i3) {
            View childAt = getChildAt(i2);
            if (childAt.getVisibility() == 0 && (cVarH = h(childAt)) != null && cVarH.b == this.f && childAt.requestFocus(i, rect)) {
                return true;
            }
            i2 += i4;
        }
        return false;
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) throws Resources.NotFoundException {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        a aVar = this.e;
        ClassLoader classLoader = savedState.e;
        if (aVar != null) {
            aVar.g(savedState.d, classLoader);
            v(savedState.c, 0, false, true);
        } else {
            this.g = savedState.c;
            this.h = savedState.d;
            this.i = classLoader;
        }
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.c = this.f;
        a aVar = this.e;
        if (aVar != null) {
            savedState.d = aVar.h();
        }
        return savedState;
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        if (i != i3) {
            int i5 = this.m;
            s(i, i3, i5, i5);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:53:0x00de  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r9) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 419
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.onTouchEvent(android.view.MotionEvent):boolean");
    }

    public final boolean p(float f) {
        boolean z;
        boolean z2;
        float f2 = this.C - f;
        this.C = f;
        float scrollX = getScrollX() + f2;
        float clientWidth = getClientWidth();
        float f3 = this.q * clientWidth;
        float f4 = this.r * clientWidth;
        ArrayList arrayList = this.b;
        boolean z3 = false;
        c cVar = (c) arrayList.get(0);
        c cVar2 = (c) android.support.v4.media.session.a.e(1, arrayList);
        if (cVar.b != 0) {
            f3 = cVar.e * clientWidth;
            z = false;
        } else {
            z = true;
        }
        if (cVar2.b != this.e.c() - 1) {
            f4 = cVar2.e * clientWidth;
            z2 = false;
        } else {
            z2 = true;
        }
        if (scrollX < f3) {
            if (z) {
                this.M.onPull(Math.abs(f3 - scrollX) / clientWidth);
                z3 = true;
            }
            scrollX = f3;
        } else if (scrollX > f4) {
            if (z2) {
                this.V.onPull(Math.abs(scrollX - f4) / clientWidth);
                z3 = true;
            }
            scrollX = f4;
        }
        int i = (int) scrollX;
        this.C = (scrollX - i) + this.C;
        scrollTo(i, getScrollY());
        o(i);
        return z3;
    }

    public final void q() {
        r(this.f);
    }

    /* JADX WARN: Code restructure failed: missing block: B:25:0x0061, code lost:
    
        r9 = null;
     */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00c8 A[PHI: r7 r11 r16 r17
  0x00c8: PHI (r7v17 int) = (r7v16 int), (r7v4 int), (r7v19 int) binds: [B:61:0x00ed, B:58:0x00d8, B:50:0x00bf] A[DONT_GENERATE, DONT_INLINE]
  0x00c8: PHI (r11v34 int) = (r11v1 int), (r11v33 int), (r11v36 int) binds: [B:61:0x00ed, B:58:0x00d8, B:50:0x00bf] A[DONT_GENERATE, DONT_INLINE]
  0x00c8: PHI (r16v4 float) = (r16v2 float), (r16v3 float), (r16v1 float) binds: [B:61:0x00ed, B:58:0x00d8, B:50:0x00bf] A[DONT_GENERATE, DONT_INLINE]
  0x00c8: PHI (r17v3 float) = (r17v2 float), (r17v2 float), (r17v5 float) binds: [B:61:0x00ed, B:58:0x00d8, B:50:0x00bf] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x014c A[PHI: r3 r13
  0x014c: PHI (r3v28 float) = (r3v26 float), (r3v27 float), (r3v25 float) binds: [B:95:0x0173, B:92:0x015d, B:85:0x0143] A[DONT_GENERATE, DONT_INLINE]
  0x014c: PHI (r13v23 int) = (r13v21 int), (r13v22 int), (r13v20 int) binds: [B:95:0x0173, B:92:0x015d, B:85:0x0143] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void r(int r19) throws android.content.res.Resources.NotFoundException {
        /*
            Method dump skipped, instructions count: 955
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.viewpager.widget.ViewPager.r(int):void");
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public final void removeView(View view) {
        if (this.t) {
            removeViewInLayout(view);
        } else {
            super.removeView(view);
        }
    }

    public final void s(int i, int i2, int i3, int i4) {
        if (i2 > 0 && !this.b.isEmpty()) {
            if (!this.j.isFinished()) {
                this.j.setFinalX(getCurrentItem() * getClientWidth());
                return;
            } else {
                scrollTo((int) ((getScrollX() / (((i2 - getPaddingLeft()) - getPaddingRight()) + i4)) * (((i - getPaddingLeft()) - getPaddingRight()) + i3)), getScrollY());
                return;
            }
        }
        c cVarJ = j(this.f);
        int iMin = (int) ((cVarJ != null ? Math.min(cVarJ.e, this.r) : DefinitionKt.NO_Float_VALUE) * ((i - getPaddingLeft()) - getPaddingRight()));
        if (iMin != getScrollX()) {
            d(false);
            scrollTo(iMin, getScrollY());
        }
    }

    public void setAdapter(a aVar) throws Resources.NotFoundException {
        ArrayList arrayList;
        a aVar2 = this.e;
        if (aVar2 != null) {
            synchronized (aVar2) {
                aVar2.b = null;
            }
            this.e.i(this);
            int i = 0;
            while (true) {
                arrayList = this.b;
                if (i >= arrayList.size()) {
                    break;
                }
                c cVar = (c) arrayList.get(i);
                this.e.a(this, cVar.b, cVar.a);
                i++;
            }
            this.e.b();
            arrayList.clear();
            int i2 = 0;
            while (i2 < getChildCount()) {
                if (!((d) getChildAt(i2).getLayoutParams()).a) {
                    removeViewAt(i2);
                    i2--;
                }
                i2++;
            }
            this.f = 0;
            scrollTo(0, 0);
        }
        this.e = aVar;
        this.a = 0;
        if (aVar != null) {
            if (this.l == null) {
                this.l = new D0(this, 2);
            }
            a aVar3 = this.e;
            D0 d0 = this.l;
            synchronized (aVar3) {
                aVar3.b = d0;
            }
            this.v = false;
            boolean z = this.W;
            this.W = true;
            this.a = this.e.c();
            if (this.g >= 0) {
                this.e.g(this.h, this.i);
                v(this.g, 0, false, true);
                this.g = -1;
                this.h = null;
                this.i = null;
            } else if (z) {
                requestLayout();
            } else {
                q();
            }
        }
        ArrayList arrayList2 = this.g1;
        if (arrayList2 == null || arrayList2.isEmpty()) {
            return;
        }
        int size = this.g1.size();
        for (int i3 = 0; i3 < size; i3++) {
            com.google.android.material.tabs.c cVar2 = (com.google.android.material.tabs.c) this.g1.get(i3);
            l lVar = cVar2.b;
            if (lVar.W == this) {
                lVar.n(aVar, cVar2.a);
            }
        }
    }

    public void setCurrentItem(int i) {
        this.v = false;
        v(i, 0, !this.W, false);
    }

    public void setOffscreenPageLimit(int i) {
        if (i < 1) {
            Log.w("ViewPager", "Requested offscreen page limit " + i + " too small; defaulting to 1");
            i = 1;
        }
        if (i != this.w) {
            this.w = i;
            q();
        }
    }

    @Deprecated
    public void setOnPageChangeListener(f fVar) {
        this.f1 = fVar;
    }

    public void setPageMargin(int i) {
        int i2 = this.m;
        this.m = i;
        int width = getWidth();
        s(width, width, i, i2);
        requestLayout();
    }

    public void setPageMarginDrawable(Drawable drawable) {
        this.n = drawable;
        if (drawable != null) {
            refreshDrawableState();
        }
        setWillNotDraw(drawable == null);
        invalidate();
    }

    public void setScrollState(int i) {
        if (this.i1 == i) {
            return;
        }
        this.i1 = i;
        f fVar = this.f1;
        if (fVar != null) {
            h hVar = (h) fVar;
            hVar.b = hVar.c;
            hVar.c = i;
            l lVar = (l) hVar.a.get();
            if (lVar != null) {
                lVar.h1 = hVar.c;
            }
        }
        ArrayList arrayList = this.e1;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i2 = 0; i2 < size; i2++) {
                f fVar2 = (f) this.e1.get(i2);
                if (fVar2 != null) {
                    h hVar2 = (h) fVar2;
                    hVar2.b = hVar2.c;
                    hVar2.c = i;
                    l lVar2 = (l) hVar2.a.get();
                    if (lVar2 != null) {
                        lVar2.h1 = hVar2.c;
                    }
                }
            }
        }
    }

    public final boolean t() {
        this.G = -1;
        this.x = false;
        this.y = false;
        VelocityTracker velocityTracker = this.H;
        if (velocityTracker != null) {
            velocityTracker.recycle();
            this.H = null;
        }
        this.M.onRelease();
        this.V.onRelease();
        return this.M.isFinished() || this.V.isFinished();
    }

    public final void u(int i, int i2, boolean z, boolean z2) {
        int scrollX;
        int iAbs;
        c cVarJ = j(i);
        int iMax = cVarJ != null ? (int) (Math.max(this.q, Math.min(cVarJ.e, this.r)) * getClientWidth()) : 0;
        if (!z) {
            if (z2) {
                f(i);
            }
            d(false);
            scrollTo(iMax, 0);
            o(iMax);
            return;
        }
        if (getChildCount() == 0) {
            setScrollingCacheEnabled(false);
        } else {
            Scroller scroller = this.j;
            if (scroller == null || scroller.isFinished()) {
                scrollX = getScrollX();
            } else {
                scrollX = this.k ? this.j.getCurrX() : this.j.getStartX();
                this.j.abortAnimation();
                setScrollingCacheEnabled(false);
            }
            int i3 = scrollX;
            int scrollY = getScrollY();
            int i4 = iMax - i3;
            int i5 = 0 - scrollY;
            if (i4 == 0 && i5 == 0) {
                d(false);
                q();
                setScrollState(0);
            } else {
                setScrollingCacheEnabled(true);
                setScrollState(2);
                int clientWidth = getClientWidth();
                int i6 = clientWidth / 2;
                float f = clientWidth;
                float f2 = i6;
                float fSin = (((float) Math.sin((Math.min(1.0f, (Math.abs(i4) * 1.0f) / f) - 0.5f) * 0.47123894f)) * f2) + f2;
                int iAbs2 = Math.abs(i2);
                if (iAbs2 > 0) {
                    iAbs = Math.round(Math.abs(fSin / iAbs2) * 1000.0f) * 4;
                } else {
                    this.e.getClass();
                    iAbs = (int) (((Math.abs(i4) / ((f * 1.0f) + this.m)) + 1.0f) * 100.0f);
                }
                int iMin = Math.min(iAbs, com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR);
                this.k = false;
                this.j.startScroll(i3, scrollY, i4, i5, iMin);
                WeakHashMap weakHashMap = V.a;
                postInvalidateOnAnimation();
            }
        }
        if (z2) {
            f(i);
        }
    }

    public final void v(int i, int i2, boolean z, boolean z2) throws Resources.NotFoundException {
        a aVar = this.e;
        if (aVar == null || aVar.c() <= 0) {
            setScrollingCacheEnabled(false);
            return;
        }
        ArrayList arrayList = this.b;
        if (!z2 && this.f == i && arrayList.size() != 0) {
            setScrollingCacheEnabled(false);
            return;
        }
        if (i < 0) {
            i = 0;
        } else if (i >= this.e.c()) {
            i = this.e.c() - 1;
        }
        int i3 = this.w;
        int i4 = this.f;
        if (i > i4 + i3 || i < i4 - i3) {
            for (int i5 = 0; i5 < arrayList.size(); i5++) {
                ((c) arrayList.get(i5)).c = true;
            }
        }
        boolean z3 = this.f != i;
        if (!this.W) {
            r(i);
            u(i, i2, z, z3);
        } else {
            this.f = i;
            if (z3) {
                f(i);
            }
            requestLayout();
        }
    }

    @Override // android.view.View
    public final boolean verifyDrawable(Drawable drawable) {
        return super.verifyDrawable(drawable) || drawable == this.n;
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        Context context = getContext();
        d dVar = new d(context, attributeSet);
        dVar.c = DefinitionKt.NO_Float_VALUE;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, j1);
        dVar.b = typedArrayObtainStyledAttributes.getInteger(0, 48);
        typedArrayObtainStyledAttributes.recycle();
        return dVar;
    }

    public void setPageMarginDrawable(int i) {
        setPageMarginDrawable(getContext().getDrawable(i));
    }

    public ViewPager(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.b = new ArrayList();
        this.c = new c();
        this.d = new Rect();
        this.g = -1;
        this.h = null;
        this.i = null;
        this.q = -3.4028235E38f;
        this.r = Float.MAX_VALUE;
        this.w = 1;
        this.G = -1;
        this.W = true;
        this.h1 = new J(this, 13);
        this.i1 = 0;
        k();
    }
}
