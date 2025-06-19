package androidx.appcompat.widget;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.AttributeSet;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewPropertyAnimator;
import android.view.Window;
import android.view.WindowInsets;
import android.widget.OverScroller;
import androidx.annotation.NonNull;
import androidx.compose.material3.C0676l1;
import androidx.core.view.InterfaceC1061s;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;

@SuppressLint({"UnknownNullness"})
/* loaded from: classes.dex */
public class ActionBarOverlayLayout extends ViewGroup implements InterfaceC0094k0, androidx.core.view.r, InterfaceC1061s {
    public static final int[] C = {R.attr.actionBarSize, android.R.attr.windowContentOverlay};
    public static final androidx.core.view.D0 D;
    public static final Rect E;
    public final C0676l1 A;
    public final C0085g B;
    public int a;
    public int b;
    public ContentFrameLayout c;
    public ActionBarContainer d;
    public InterfaceC0096l0 e;
    public Drawable f;
    public boolean g;
    public boolean h;
    public boolean i;
    public boolean j;
    public int k;
    public int l;
    public final Rect m;
    public final Rect n;
    public final Rect o;
    public final Rect p;
    public androidx.core.view.D0 q;
    public androidx.core.view.D0 r;
    public androidx.core.view.D0 s;
    public androidx.core.view.D0 t;
    public InterfaceC0081e u;
    public OverScroller v;
    public ViewPropertyAnimator w;
    public final C0076c x;
    public final RunnableC0079d y;
    public final RunnableC0079d z;

    static {
        int i = Build.VERSION.SDK_INT;
        androidx.core.view.s0 r0Var = i >= 34 ? new androidx.core.view.r0() : i >= 30 ? new androidx.core.view.q0() : i >= 29 ? new androidx.core.view.p0() : new androidx.core.view.n0();
        r0Var.g(androidx.core.graphics.e.b(0, 1, 0, 1));
        D = r0Var.b();
        E = new Rect();
    }

    public ActionBarOverlayLayout(@NonNull Context context) {
        this(context, null);
    }

    public static boolean a(View view, Rect rect, boolean z) {
        boolean z2;
        C0083f c0083f = (C0083f) view.getLayoutParams();
        int i = ((ViewGroup.MarginLayoutParams) c0083f).leftMargin;
        int i2 = rect.left;
        if (i != i2) {
            ((ViewGroup.MarginLayoutParams) c0083f).leftMargin = i2;
            z2 = true;
        } else {
            z2 = false;
        }
        int i3 = ((ViewGroup.MarginLayoutParams) c0083f).topMargin;
        int i4 = rect.top;
        if (i3 != i4) {
            ((ViewGroup.MarginLayoutParams) c0083f).topMargin = i4;
            z2 = true;
        }
        int i5 = ((ViewGroup.MarginLayoutParams) c0083f).rightMargin;
        int i6 = rect.right;
        if (i5 != i6) {
            ((ViewGroup.MarginLayoutParams) c0083f).rightMargin = i6;
            z2 = true;
        }
        if (z) {
            int i7 = ((ViewGroup.MarginLayoutParams) c0083f).bottomMargin;
            int i8 = rect.bottom;
            if (i7 != i8) {
                ((ViewGroup.MarginLayoutParams) c0083f).bottomMargin = i8;
                return true;
            }
        }
        return z2;
    }

    public final void b() {
        removeCallbacks(this.y);
        removeCallbacks(this.z);
        ViewPropertyAnimator viewPropertyAnimator = this.w;
        if (viewPropertyAnimator != null) {
            viewPropertyAnimator.cancel();
        }
    }

    @Override // androidx.core.view.r
    public final void c(int i, View view) {
        if (i == 0) {
            onStopNestedScroll(view);
        }
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof C0083f;
    }

    public final void d(Context context) {
        TypedArray typedArrayObtainStyledAttributes = getContext().getTheme().obtainStyledAttributes(C);
        this.a = typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
        Drawable drawable = typedArrayObtainStyledAttributes.getDrawable(1);
        this.f = drawable;
        setWillNotDraw(drawable == null);
        typedArrayObtainStyledAttributes.recycle();
        this.v = new OverScroller(context);
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        int translationY;
        super.draw(canvas);
        if (this.f != null) {
            if (this.d.getVisibility() == 0) {
                translationY = (int) (this.d.getTranslationY() + this.d.getBottom() + 0.5f);
            } else {
                translationY = 0;
            }
            this.f.setBounds(0, translationY, getWidth(), this.f.getIntrinsicHeight() + translationY);
            this.f.draw(canvas);
        }
    }

    @Override // androidx.core.view.InterfaceC1061s
    public final void e(View view, int i, int i2, int i3, int i4, int i5, int[] iArr) {
        f(view, i, i2, i3, i4, i5);
    }

    @Override // androidx.core.view.r
    public final void f(View view, int i, int i2, int i3, int i4, int i5) {
        if (i5 == 0) {
            onNestedScroll(view, i, i2, i3, i4);
        }
    }

    @Override // android.view.View
    public final boolean fitSystemWindows(Rect rect) {
        return super.fitSystemWindows(rect);
    }

    @Override // androidx.core.view.r
    public final boolean g(View view, View view2, int i, int i2) {
        return i2 == 0 && onStartNestedScroll(view, view2, i);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new C0083f(-1, -1);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C0083f(getContext(), attributeSet);
    }

    public int getActionBarHideOffset() {
        ActionBarContainer actionBarContainer = this.d;
        if (actionBarContainer != null) {
            return -((int) actionBarContainer.getTranslationY());
        }
        return 0;
    }

    @Override // android.view.ViewGroup
    public int getNestedScrollAxes() {
        C0676l1 c0676l1 = this.A;
        return c0676l1.b | c0676l1.a;
    }

    public CharSequence getTitle() {
        k();
        return ((x1) this.e).a.getTitle();
    }

    @Override // androidx.core.view.r
    public final void h(View view, View view2, int i, int i2) {
        if (i2 == 0) {
            onNestedScrollAccepted(view, view2, i);
        }
    }

    @Override // androidx.core.view.r
    public final void i(View view, int i, int i2, int[] iArr, int i3) {
    }

    public final void j(int i) {
        k();
        if (i == 2) {
            ((x1) this.e).getClass();
            Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
        } else if (i == 5) {
            ((x1) this.e).getClass();
            Log.i("ToolbarWidgetWrapper", "Progress display unsupported");
        } else {
            if (i != 109) {
                return;
            }
            setOverlayMode(true);
        }
    }

    public final void k() {
        InterfaceC0096l0 wrapper;
        if (this.c == null) {
            this.c = (ContentFrameLayout) findViewById(R.id.action_bar_activity_content);
            this.d = (ActionBarContainer) findViewById(R.id.action_bar_container);
            KeyEvent.Callback callbackFindViewById = findViewById(R.id.action_bar);
            if (callbackFindViewById instanceof InterfaceC0096l0) {
                wrapper = (InterfaceC0096l0) callbackFindViewById;
            } else {
                if (!(callbackFindViewById instanceof Toolbar)) {
                    throw new IllegalStateException("Can't make a decor toolbar out of ".concat(callbackFindViewById.getClass().getSimpleName()));
                }
                wrapper = ((Toolbar) callbackFindViewById).getWrapper();
            }
            this.e = wrapper;
        }
    }

    public final void l(androidx.appcompat.view.menu.n nVar, androidx.appcompat.view.menu.y yVar) {
        k();
        x1 x1Var = (x1) this.e;
        C0095l c0095l = x1Var.m;
        Toolbar toolbar = x1Var.a;
        if (c0095l == null) {
            x1Var.m = new C0095l(toolbar.getContext());
        }
        C0095l c0095l2 = x1Var.m;
        c0095l2.e = yVar;
        if (nVar == null && toolbar.a == null) {
            return;
        }
        toolbar.f();
        androidx.appcompat.view.menu.n nVar2 = toolbar.a.p;
        if (nVar2 == nVar) {
            return;
        }
        if (nVar2 != null) {
            nVar2.r(toolbar.L);
            nVar2.r(toolbar.M);
        }
        if (toolbar.M == null) {
            toolbar.M = new s1(toolbar);
        }
        c0095l2.q = true;
        if (nVar != null) {
            nVar.b(c0095l2, toolbar.j);
            nVar.b(toolbar.M, toolbar.j);
        } else {
            c0095l2.g(toolbar.j, null);
            toolbar.M.g(toolbar.j, null);
            c0095l2.h();
            toolbar.M.h();
        }
        toolbar.a.setPopupTheme(toolbar.k);
        toolbar.a.setPresenter(c0095l2);
        toolbar.L = c0095l2;
        toolbar.w();
    }

    @Override // android.view.View
    public final WindowInsets onApplyWindowInsets(WindowInsets windowInsets) {
        k();
        androidx.core.view.D0 d0H = androidx.core.view.D0.h(this, windowInsets);
        boolean zA = a(this.d, new Rect(d0H.b(), d0H.d(), d0H.c(), d0H.a()), false);
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        Rect rect = this.m;
        androidx.core.view.L.b(this, d0H, rect);
        int i = rect.left;
        int i2 = rect.top;
        int i3 = rect.right;
        int i4 = rect.bottom;
        androidx.core.view.z0 z0Var = d0H.a;
        androidx.core.view.D0 d0N = z0Var.n(i, i2, i3, i4);
        this.q = d0N;
        boolean z = true;
        if (!this.r.equals(d0N)) {
            this.r = this.q;
            zA = true;
        }
        Rect rect2 = this.n;
        if (rect2.equals(rect)) {
            z = zA;
        } else {
            rect2.set(rect);
        }
        if (z) {
            requestLayout();
        }
        return z0Var.a().a.c().a.b().g();
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        d(getContext());
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.J.c(this);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        b();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int childCount = getChildCount();
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        for (int i5 = 0; i5 < childCount; i5++) {
            View childAt = getChildAt(i5);
            if (childAt.getVisibility() != 8) {
                C0083f c0083f = (C0083f) childAt.getLayoutParams();
                int measuredWidth = childAt.getMeasuredWidth();
                int measuredHeight = childAt.getMeasuredHeight();
                int i6 = ((ViewGroup.MarginLayoutParams) c0083f).leftMargin + paddingLeft;
                int i7 = ((ViewGroup.MarginLayoutParams) c0083f).topMargin + paddingTop;
                childAt.layout(i6, i7, measuredWidth + i6, measuredHeight + i7);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:22:0x00aa  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onMeasure(int r13, int r14) {
        /*
            Method dump skipped, instructions count: 381
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.ActionBarOverlayLayout.onMeasure(int, int):void");
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedFling(View view, float f, float f2, boolean z) {
        if (!this.i || !z) {
            return false;
        }
        this.v.fling(0, 0, 0, (int) f2, 0, 0, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        if (this.v.getFinalY() > this.d.getHeight()) {
            b();
            this.z.run();
        } else {
            b();
            this.y.run();
        }
        this.j = true;
        return true;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedPreFling(View view, float f, float f2) {
        return false;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onNestedPreScroll(View view, int i, int i2, int[] iArr) {
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onNestedScroll(View view, int i, int i2, int i3, int i4) {
        int i5 = this.k + i2;
        this.k = i5;
        setActionBarHideOffset(i5);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onNestedScrollAccepted(View view, View view2, int i) {
        androidx.appcompat.app.T t;
        androidx.appcompat.view.k kVar;
        this.A.a = i;
        this.k = getActionBarHideOffset();
        b();
        InterfaceC0081e interfaceC0081e = this.u;
        if (interfaceC0081e == null || (kVar = (t = (androidx.appcompat.app.T) interfaceC0081e).t) == null) {
            return;
        }
        kVar.a();
        t.t = null;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onStartNestedScroll(View view, View view2, int i) {
        if ((i & 2) == 0 || this.d.getVisibility() != 0) {
            return false;
        }
        return this.i;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onStopNestedScroll(View view) {
        if (!this.i || this.j) {
            return;
        }
        if (this.k <= this.d.getHeight()) {
            b();
            postDelayed(this.y, 600L);
        } else {
            b();
            postDelayed(this.z, 600L);
        }
    }

    @Override // android.view.View
    public final void onWindowSystemUiVisibilityChanged(int i) {
        super.onWindowSystemUiVisibilityChanged(i);
        k();
        int i2 = this.l ^ i;
        this.l = i;
        boolean z = (i & 4) == 0;
        boolean z2 = (i & 256) != 0;
        InterfaceC0081e interfaceC0081e = this.u;
        if (interfaceC0081e != null) {
            androidx.appcompat.app.T t = (androidx.appcompat.app.T) interfaceC0081e;
            t.o = !z2;
            if (z || !z2) {
                if (t.q) {
                    t.q = false;
                    t.J(true);
                }
            } else if (!t.q) {
                t.q = true;
                t.J(true);
            }
        }
        if ((i2 & 256) == 0 || this.u == null) {
            return;
        }
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        androidx.core.view.J.c(this);
    }

    @Override // android.view.View
    public final void onWindowVisibilityChanged(int i) {
        super.onWindowVisibilityChanged(i);
        this.b = i;
        InterfaceC0081e interfaceC0081e = this.u;
        if (interfaceC0081e != null) {
            ((androidx.appcompat.app.T) interfaceC0081e).n = i;
        }
    }

    public void setActionBarHideOffset(int i) {
        b();
        this.d.setTranslationY(-Math.max(0, Math.min(i, this.d.getHeight())));
    }

    public void setActionBarVisibilityCallback(InterfaceC0081e interfaceC0081e) {
        this.u = interfaceC0081e;
        if (getWindowToken() != null) {
            ((androidx.appcompat.app.T) this.u).n = this.b;
            int i = this.l;
            if (i != 0) {
                onWindowSystemUiVisibilityChanged(i);
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                androidx.core.view.J.c(this);
            }
        }
    }

    public void setHasNonEmbeddedTabs(boolean z) {
        this.h = z;
    }

    public void setHideOnContentScrollEnabled(boolean z) {
        if (z != this.i) {
            this.i = z;
            if (z) {
                return;
            }
            b();
            setActionBarHideOffset(0);
        }
    }

    public void setIcon(int i) {
        k();
        x1 x1Var = (x1) this.e;
        x1Var.d = i != 0 ? com.facebook.appevents.g.f(x1Var.a.getContext(), i) : null;
        x1Var.c();
    }

    public void setLogo(int i) {
        k();
        x1 x1Var = (x1) this.e;
        x1Var.e = i != 0 ? com.facebook.appevents.g.f(x1Var.a.getContext(), i) : null;
        x1Var.c();
    }

    public void setOverlayMode(boolean z) {
        this.g = z;
    }

    public void setShowingForActionMode(boolean z) {
    }

    public void setUiOptions(int i) {
    }

    @Override // androidx.appcompat.widget.InterfaceC0094k0
    public void setWindowCallback(Window.Callback callback) {
        k();
        ((x1) this.e).k = callback;
    }

    @Override // androidx.appcompat.widget.InterfaceC0094k0
    public void setWindowTitle(CharSequence charSequence) {
        k();
        x1 x1Var = (x1) this.e;
        if (x1Var.g) {
            return;
        }
        x1Var.h = charSequence;
        if ((x1Var.b & 8) != 0) {
            Toolbar toolbar = x1Var.a;
            toolbar.setTitle(charSequence);
            if (x1Var.g) {
                androidx.core.view.V.q(toolbar.getRootView(), charSequence);
            }
        }
    }

    @Override // android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return false;
    }

    public ActionBarOverlayLayout(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.b = 0;
        this.m = new Rect();
        this.n = new Rect();
        this.o = new Rect();
        this.p = new Rect();
        new Rect();
        new Rect();
        new Rect();
        new Rect();
        androidx.core.view.D0 d0 = androidx.core.view.D0.b;
        this.q = d0;
        this.r = d0;
        this.s = d0;
        this.t = d0;
        this.x = new C0076c(this, 0);
        this.y = new RunnableC0079d(this, 0);
        this.z = new RunnableC0079d(this, 1);
        d(context);
        this.A = new C0676l1();
        C0085g c0085g = new C0085g(context);
        c0085g.setWillNotDraw(true);
        this.B = c0085g;
        addView(c0085g);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return new C0083f(layoutParams);
    }

    public void setIcon(Drawable drawable) {
        k();
        x1 x1Var = (x1) this.e;
        x1Var.d = drawable;
        x1Var.c();
    }
}
