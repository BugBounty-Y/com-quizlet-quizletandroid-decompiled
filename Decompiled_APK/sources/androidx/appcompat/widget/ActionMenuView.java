package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.ContextThemeWrapper;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityEvent;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.appcompat.view.menu.ActionMenuItemView;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class ActionMenuView extends LinearLayoutCompat implements androidx.appcompat.view.menu.m, androidx.appcompat.view.menu.B {
    public InterfaceC0101o A;
    public androidx.appcompat.view.menu.n p;
    public Context q;
    public int r;
    public boolean s;
    public C0095l t;
    public androidx.appcompat.app.K u;
    public androidx.appcompat.view.menu.l v;
    public boolean w;
    public int x;
    public final int y;
    public final int z;

    public ActionMenuView(@NonNull Context context) {
        this(context, null);
    }

    public static C0099n l() {
        C0099n c0099n = new C0099n(-2, -2);
        c0099n.a = false;
        ((LinearLayout.LayoutParams) c0099n).gravity = 16;
        return c0099n;
    }

    public static C0099n m(ViewGroup.LayoutParams layoutParams) {
        C0099n c0099n;
        if (layoutParams == null) {
            return l();
        }
        if (layoutParams instanceof C0099n) {
            C0099n c0099n2 = (C0099n) layoutParams;
            c0099n = new C0099n(c0099n2);
            c0099n.a = c0099n2.a;
        } else {
            c0099n = new C0099n(layoutParams);
        }
        if (((LinearLayout.LayoutParams) c0099n).gravity <= 0) {
            ((LinearLayout.LayoutParams) c0099n).gravity = 16;
        }
        return c0099n;
    }

    @Override // androidx.appcompat.view.menu.m
    public final boolean a(androidx.appcompat.view.menu.p pVar) {
        return this.p.q(pVar, null, 0);
    }

    @Override // androidx.appcompat.view.menu.B
    public final void b(androidx.appcompat.view.menu.n nVar) {
        this.p = nVar;
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return layoutParams instanceof C0099n;
    }

    @Override // android.view.View
    public final boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        return false;
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.ViewGroup
    public final /* bridge */ /* synthetic */ ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return l();
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.ViewGroup
    public final /* bridge */ /* synthetic */ ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return m(layoutParams);
    }

    public Menu getMenu() {
        if (this.p == null) {
            Context context = getContext();
            androidx.appcompat.view.menu.n nVar = new androidx.appcompat.view.menu.n(context);
            this.p = nVar;
            nVar.e = new com.google.android.gms.internal.instantapps.a(this, 2);
            C0095l c0095l = new C0095l(context);
            this.t = c0095l;
            c0095l.l = true;
            c0095l.m = true;
            androidx.appcompat.view.menu.y uVar = this.u;
            if (uVar == null) {
                uVar = new com.google.android.gms.internal.mlkit_common.u(1);
            }
            c0095l.e = uVar;
            this.p.b(c0095l, this.q);
            C0095l c0095l2 = this.t;
            c0095l2.h = this;
            this.p = c0095l2.c;
        }
        return this.p;
    }

    public Drawable getOverflowIcon() {
        getMenu();
        C0095l c0095l = this.t;
        C0093k c0093k = c0095l.i;
        if (c0093k != null) {
            return c0093k.getDrawable();
        }
        if (c0095l.k) {
            return c0095l.j;
        }
        return null;
    }

    public int getPopupTheme() {
        return this.r;
    }

    public int getWindowAnimations() {
        return 0;
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat
    /* renamed from: h */
    public final /* bridge */ /* synthetic */ C0121y0 generateDefaultLayoutParams() {
        return l();
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat
    /* renamed from: i */
    public final C0121y0 generateLayoutParams(AttributeSet attributeSet) {
        return new C0099n(getContext(), attributeSet);
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat
    /* renamed from: j */
    public final /* bridge */ /* synthetic */ C0121y0 generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return m(layoutParams);
    }

    public final boolean n(int i) {
        boolean zA = false;
        if (i == 0) {
            return false;
        }
        KeyEvent.Callback childAt = getChildAt(i - 1);
        KeyEvent.Callback childAt2 = getChildAt(i);
        if (i < getChildCount() && (childAt instanceof InterfaceC0097m)) {
            zA = ((InterfaceC0097m) childAt).a();
        }
        return (i <= 0 || !(childAt2 instanceof InterfaceC0097m)) ? zA : ((InterfaceC0097m) childAt2).b() | zA;
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        C0095l c0095l = this.t;
        if (c0095l != null) {
            c0095l.h();
            if (this.t.i()) {
                this.t.f();
                this.t.l();
            }
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        C0095l c0095l = this.t;
        if (c0095l != null) {
            c0095l.f();
            C0087h c0087h = c0095l.t;
            if (c0087h == null || !c0087h.b()) {
                return;
            }
            c0087h.i.dismiss();
        }
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int width;
        int paddingLeft;
        if (!this.w) {
            super.onLayout(z, i, i2, i3, i4);
            return;
        }
        int childCount = getChildCount();
        int i5 = (i4 - i2) / 2;
        int dividerWidth = getDividerWidth();
        int i6 = i3 - i;
        int paddingRight = (i6 - getPaddingRight()) - getPaddingLeft();
        boolean z2 = C1.a;
        boolean z3 = getLayoutDirection() == 1;
        int i7 = 0;
        int i8 = 0;
        for (int i9 = 0; i9 < childCount; i9++) {
            View childAt = getChildAt(i9);
            if (childAt.getVisibility() != 8) {
                C0099n c0099n = (C0099n) childAt.getLayoutParams();
                if (c0099n.a) {
                    int measuredWidth = childAt.getMeasuredWidth();
                    if (n(i9)) {
                        measuredWidth += dividerWidth;
                    }
                    int measuredHeight = childAt.getMeasuredHeight();
                    if (z3) {
                        paddingLeft = getPaddingLeft() + ((LinearLayout.LayoutParams) c0099n).leftMargin;
                        width = paddingLeft + measuredWidth;
                    } else {
                        width = (getWidth() - getPaddingRight()) - ((LinearLayout.LayoutParams) c0099n).rightMargin;
                        paddingLeft = width - measuredWidth;
                    }
                    int i10 = i5 - (measuredHeight / 2);
                    childAt.layout(paddingLeft, i10, width, measuredHeight + i10);
                    paddingRight -= measuredWidth;
                    i7 = 1;
                } else {
                    paddingRight -= (childAt.getMeasuredWidth() + ((LinearLayout.LayoutParams) c0099n).leftMargin) + ((LinearLayout.LayoutParams) c0099n).rightMargin;
                    n(i9);
                    i8++;
                }
            }
        }
        if (childCount == 1 && i7 == 0) {
            View childAt2 = getChildAt(0);
            int measuredWidth2 = childAt2.getMeasuredWidth();
            int measuredHeight2 = childAt2.getMeasuredHeight();
            int i11 = (i6 / 2) - (measuredWidth2 / 2);
            int i12 = i5 - (measuredHeight2 / 2);
            childAt2.layout(i11, i12, measuredWidth2 + i11, measuredHeight2 + i12);
            return;
        }
        int i13 = i8 - (i7 ^ 1);
        int iMax = Math.max(0, i13 > 0 ? paddingRight / i13 : 0);
        if (z3) {
            int width2 = getWidth() - getPaddingRight();
            for (int i14 = 0; i14 < childCount; i14++) {
                View childAt3 = getChildAt(i14);
                C0099n c0099n2 = (C0099n) childAt3.getLayoutParams();
                if (childAt3.getVisibility() != 8 && !c0099n2.a) {
                    int i15 = width2 - ((LinearLayout.LayoutParams) c0099n2).rightMargin;
                    int measuredWidth3 = childAt3.getMeasuredWidth();
                    int measuredHeight3 = childAt3.getMeasuredHeight();
                    int i16 = i5 - (measuredHeight3 / 2);
                    childAt3.layout(i15 - measuredWidth3, i16, i15, measuredHeight3 + i16);
                    width2 = i15 - ((measuredWidth3 + ((LinearLayout.LayoutParams) c0099n2).leftMargin) + iMax);
                }
            }
            return;
        }
        int paddingLeft2 = getPaddingLeft();
        for (int i17 = 0; i17 < childCount; i17++) {
            View childAt4 = getChildAt(i17);
            C0099n c0099n3 = (C0099n) childAt4.getLayoutParams();
            if (childAt4.getVisibility() != 8 && !c0099n3.a) {
                int i18 = paddingLeft2 + ((LinearLayout.LayoutParams) c0099n3).leftMargin;
                int measuredWidth4 = childAt4.getMeasuredWidth();
                int measuredHeight4 = childAt4.getMeasuredHeight();
                int i19 = i5 - (measuredHeight4 / 2);
                childAt4.layout(i18, i19, i18 + measuredWidth4, measuredHeight4 + i19);
                paddingLeft2 = measuredWidth4 + ((LinearLayout.LayoutParams) c0099n3).rightMargin + iMax + i18;
            }
        }
    }

    /* JADX WARN: Type inference failed for: r11v14 */
    /* JADX WARN: Type inference failed for: r11v15, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r11v17 */
    /* JADX WARN: Type inference failed for: r11v40 */
    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.View
    public final void onMeasure(int i, int i2) {
        int i3;
        int i4;
        ?? r11;
        int i5;
        int i6;
        androidx.appcompat.view.menu.n nVar;
        boolean z = this.w;
        boolean z2 = View.MeasureSpec.getMode(i) == 1073741824;
        this.w = z2;
        if (z != z2) {
            this.x = 0;
        }
        int size = View.MeasureSpec.getSize(i);
        if (this.w && (nVar = this.p) != null && size != this.x) {
            this.x = size;
            nVar.p(true);
        }
        int childCount = getChildCount();
        if (!this.w || childCount <= 0) {
            for (int i7 = 0; i7 < childCount; i7++) {
                C0099n c0099n = (C0099n) getChildAt(i7).getLayoutParams();
                ((LinearLayout.LayoutParams) c0099n).rightMargin = 0;
                ((LinearLayout.LayoutParams) c0099n).leftMargin = 0;
            }
            super.onMeasure(i, i2);
            return;
        }
        int mode = View.MeasureSpec.getMode(i2);
        int size2 = View.MeasureSpec.getSize(i);
        int size3 = View.MeasureSpec.getSize(i2);
        int paddingRight = getPaddingRight() + getPaddingLeft();
        int paddingBottom = getPaddingBottom() + getPaddingTop();
        int childMeasureSpec = ViewGroup.getChildMeasureSpec(i2, paddingBottom, -2);
        int i8 = size2 - paddingRight;
        int i9 = this.y;
        int i10 = i8 / i9;
        int i11 = i8 % i9;
        if (i10 == 0) {
            setMeasuredDimension(i8, 0);
            return;
        }
        int i12 = (i11 / i10) + i9;
        int childCount2 = getChildCount();
        int iMax = 0;
        int i13 = 0;
        int iMax2 = 0;
        int i14 = 0;
        boolean z3 = false;
        int i15 = 0;
        long j = 0;
        while (true) {
            i3 = this.z;
            if (i14 >= childCount2) {
                break;
            }
            View childAt = getChildAt(i14);
            int i16 = size3;
            int i17 = paddingBottom;
            if (childAt.getVisibility() == 8) {
                i5 = i12;
            } else {
                boolean z4 = childAt instanceof ActionMenuItemView;
                i13++;
                if (z4) {
                    childAt.setPadding(i3, 0, i3, 0);
                }
                C0099n c0099n2 = (C0099n) childAt.getLayoutParams();
                c0099n2.f = false;
                c0099n2.c = 0;
                c0099n2.b = 0;
                c0099n2.d = false;
                ((LinearLayout.LayoutParams) c0099n2).leftMargin = 0;
                ((LinearLayout.LayoutParams) c0099n2).rightMargin = 0;
                c0099n2.e = z4 && !TextUtils.isEmpty(((ActionMenuItemView) childAt).getText());
                int i18 = c0099n2.a ? 1 : i10;
                C0099n c0099n3 = (C0099n) childAt.getLayoutParams();
                int i19 = i10;
                i5 = i12;
                int iMakeMeasureSpec = View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(childMeasureSpec) - i17, View.MeasureSpec.getMode(childMeasureSpec));
                ActionMenuItemView actionMenuItemView = z4 ? (ActionMenuItemView) childAt : null;
                boolean z5 = (actionMenuItemView == null || TextUtils.isEmpty(actionMenuItemView.getText())) ? false : true;
                boolean z6 = z5;
                if (i18 <= 0 || (z5 && i18 < 2)) {
                    i6 = 0;
                } else {
                    childAt.measure(View.MeasureSpec.makeMeasureSpec(i5 * i18, Integer.MIN_VALUE), iMakeMeasureSpec);
                    int measuredWidth = childAt.getMeasuredWidth();
                    i6 = measuredWidth / i5;
                    if (measuredWidth % i5 != 0) {
                        i6++;
                    }
                    if (z6 && i6 < 2) {
                        i6 = 2;
                    }
                }
                c0099n3.d = !c0099n3.a && z6;
                c0099n3.b = i6;
                childAt.measure(View.MeasureSpec.makeMeasureSpec(i6 * i5, 1073741824), iMakeMeasureSpec);
                iMax2 = Math.max(iMax2, i6);
                if (c0099n2.d) {
                    i15++;
                }
                if (c0099n2.a) {
                    z3 = true;
                }
                i10 = i19 - i6;
                iMax = Math.max(iMax, childAt.getMeasuredHeight());
                if (i6 == 1) {
                    j |= 1 << i14;
                }
            }
            i14++;
            size3 = i16;
            paddingBottom = i17;
            i12 = i5;
        }
        int i20 = size3;
        int i21 = i10;
        int i22 = i12;
        boolean z7 = z3 && i13 == 2;
        int i23 = i21;
        boolean z8 = false;
        while (i15 > 0 && i23 > 0) {
            int i24 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            long j2 = 0;
            int i25 = 0;
            int i26 = 0;
            while (i26 < childCount2) {
                boolean z9 = z7;
                C0099n c0099n4 = (C0099n) getChildAt(i26).getLayoutParams();
                int i27 = iMax;
                if (c0099n4.d) {
                    int i28 = c0099n4.b;
                    if (i28 < i24) {
                        j2 = 1 << i26;
                        i24 = i28;
                        i25 = 1;
                    } else if (i28 == i24) {
                        j2 |= 1 << i26;
                        i25++;
                    }
                }
                i26++;
                iMax = i27;
                z7 = z9;
            }
            boolean z10 = z7;
            i4 = iMax;
            j |= j2;
            if (i25 > i23) {
                break;
            }
            int i29 = i24 + 1;
            int i30 = 0;
            while (i30 < childCount2) {
                View childAt2 = getChildAt(i30);
                C0099n c0099n5 = (C0099n) childAt2.getLayoutParams();
                boolean z11 = z3;
                long j3 = 1 << i30;
                if ((j2 & j3) != 0) {
                    if (z10 && c0099n5.e) {
                        r11 = 1;
                        r11 = 1;
                        if (i23 == 1) {
                            childAt2.setPadding(i3 + i22, 0, i3, 0);
                        }
                    } else {
                        r11 = 1;
                    }
                    c0099n5.b += r11;
                    c0099n5.f = r11;
                    i23--;
                } else if (c0099n5.b == i29) {
                    j |= j3;
                }
                i30++;
                z3 = z11;
            }
            iMax = i4;
            z7 = z10;
            z8 = true;
        }
        i4 = iMax;
        boolean z12 = !z3 && i13 == 1;
        if (i23 > 0 && j != 0 && (i23 < i13 - 1 || z12 || iMax2 > 1)) {
            float fBitCount = Long.bitCount(j);
            if (!z12) {
                if ((j & 1) != 0 && !((C0099n) getChildAt(0).getLayoutParams()).e) {
                    fBitCount -= 0.5f;
                }
                int i31 = childCount2 - 1;
                if ((j & (1 << i31)) != 0 && !((C0099n) getChildAt(i31).getLayoutParams()).e) {
                    fBitCount -= 0.5f;
                }
            }
            int i32 = fBitCount > DefinitionKt.NO_Float_VALUE ? (int) ((i23 * i22) / fBitCount) : 0;
            boolean z13 = z8;
            for (int i33 = 0; i33 < childCount2; i33++) {
                if ((j & (1 << i33)) != 0) {
                    View childAt3 = getChildAt(i33);
                    C0099n c0099n6 = (C0099n) childAt3.getLayoutParams();
                    if (childAt3 instanceof ActionMenuItemView) {
                        c0099n6.c = i32;
                        c0099n6.f = true;
                        if (i33 == 0 && !c0099n6.e) {
                            ((LinearLayout.LayoutParams) c0099n6).leftMargin = (-i32) / 2;
                        }
                        z13 = true;
                    } else if (c0099n6.a) {
                        c0099n6.c = i32;
                        c0099n6.f = true;
                        ((LinearLayout.LayoutParams) c0099n6).rightMargin = (-i32) / 2;
                        z13 = true;
                    } else {
                        if (i33 != 0) {
                            ((LinearLayout.LayoutParams) c0099n6).leftMargin = i32 / 2;
                        }
                        if (i33 != childCount2 - 1) {
                            ((LinearLayout.LayoutParams) c0099n6).rightMargin = i32 / 2;
                        }
                    }
                }
            }
            z8 = z13;
        }
        if (z8) {
            for (int i34 = 0; i34 < childCount2; i34++) {
                View childAt4 = getChildAt(i34);
                C0099n c0099n7 = (C0099n) childAt4.getLayoutParams();
                if (c0099n7.f) {
                    childAt4.measure(View.MeasureSpec.makeMeasureSpec((c0099n7.b * i22) + c0099n7.c, 1073741824), childMeasureSpec);
                }
            }
        }
        setMeasuredDimension(i8, mode != 1073741824 ? i4 : i20);
    }

    public void setExpandedActionViewsExclusive(boolean z) {
        this.t.q = z;
    }

    public void setOnMenuItemClickListener(InterfaceC0101o interfaceC0101o) {
        this.A = interfaceC0101o;
    }

    public void setOverflowIcon(Drawable drawable) {
        getMenu();
        C0095l c0095l = this.t;
        C0093k c0093k = c0095l.i;
        if (c0093k != null) {
            c0093k.setImageDrawable(drawable);
        } else {
            c0095l.k = true;
            c0095l.j = drawable;
        }
    }

    public void setOverflowReserved(boolean z) {
        this.s = z;
    }

    public void setPopupTheme(int i) {
        if (this.r != i) {
            this.r = i;
            if (i == 0) {
                this.q = getContext();
            } else {
                this.q = new ContextThemeWrapper(getContext(), i);
            }
        }
    }

    public void setPresenter(C0095l c0095l) {
        this.t = c0095l;
        c0095l.h = this;
        this.p = c0095l.c;
    }

    public ActionMenuView(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        setBaselineAligned(false);
        float f = context.getResources().getDisplayMetrics().density;
        this.y = (int) (56.0f * f);
        this.z = (int) (f * 4.0f);
        this.q = context;
        this.r = 0;
    }

    @Override // androidx.appcompat.widget.LinearLayoutCompat, android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C0099n(getContext(), attributeSet);
    }
}
