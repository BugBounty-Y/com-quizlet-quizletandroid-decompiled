package androidx.viewpager2.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.annotation.NonNull;
import androidx.appcompat.app.Q;
import androidx.core.view.V;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.AbstractC1373j0;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.work.impl.model.n;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class ViewPager2 extends ViewGroup {
    public final Rect a;
    public final Rect b;
    public final f c;
    public int d;
    public boolean e;
    public final e f;
    public h g;
    public int h;
    public Parcelable i;
    public l j;
    public k k;
    public d l;
    public f m;
    public com.airbnb.lottie.network.d n;
    public b o;
    public AbstractC1373j0 p;
    public boolean q;
    public boolean r;
    public int s;
    public n t;

    public static class SavedState extends View.BaseSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new m();
        public int a;
        public int b;
        public Parcelable c;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.a);
            parcel.writeInt(this.b);
            parcel.writeParcelable(this.c, i);
        }
    }

    public ViewPager2(@NonNull Context context) {
        super(context);
        this.a = new Rect();
        this.b = new Rect();
        this.c = new f();
        this.e = false;
        this.f = new e(this, 0);
        this.h = -1;
        this.p = null;
        this.q = false;
        this.r = true;
        this.s = -1;
        a(context, null);
    }

    public final void a(Context context, AttributeSet attributeSet) {
        this.t = new n(this);
        l lVar = new l(this, context);
        this.j = lVar;
        lVar.setId(View.generateViewId());
        this.j.setDescendantFocusability(131072);
        h hVar = new h(this, context);
        this.g = hVar;
        this.j.setLayoutManager(hVar);
        this.j.setScrollingTouchSlop(1);
        int[] iArr = androidx.viewpager2.a.a;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, iArr);
        V.n(this, context, iArr, attributeSet, typedArrayObtainStyledAttributes, 0);
        try {
            setOrientation(typedArrayObtainStyledAttributes.getInt(0, 0));
            typedArrayObtainStyledAttributes.recycle();
            this.j.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
            this.j.j(new g());
            d dVar = new d(this);
            this.l = dVar;
            this.n = new com.airbnb.lottie.network.d(dVar, 15);
            k kVar = new k(this);
            this.k = kVar;
            kVar.a(this.j);
            this.j.k(this.l);
            f fVar = new f();
            this.m = fVar;
            this.l.a = fVar;
            f fVar2 = new f(this, 0);
            f fVar3 = new f(this, 1);
            ((ArrayList) fVar.b).add(fVar2);
            ((ArrayList) this.m.b).add(fVar3);
            n nVar = this.t;
            l lVar2 = this.j;
            nVar.getClass();
            lVar2.setImportantForAccessibility(2);
            nVar.c = new e(nVar, 1);
            ViewPager2 viewPager2 = (ViewPager2) nVar.d;
            if (viewPager2.getImportantForAccessibility() == 0) {
                viewPager2.setImportantForAccessibility(1);
            }
            f fVar4 = this.m;
            ((ArrayList) fVar4.b).add(this.c);
            b bVar = new b();
            this.o = bVar;
            ((ArrayList) this.m.b).add(bVar);
            l lVar3 = this.j;
            attachViewToParent(lVar3, 0, lVar3.getLayoutParams());
        } catch (Throwable th) {
            typedArrayObtainStyledAttributes.recycle();
            throw th;
        }
    }

    public final void b() {
        AbstractC1361d0 adapter;
        if (this.h == -1 || (adapter = getAdapter()) == null) {
            return;
        }
        if (this.i != null) {
            this.i = null;
        }
        int iMax = Math.max(0, Math.min(this.h, adapter.getItemCount() - 1));
        this.d = iMax;
        this.h = -1;
        this.j.k0(iMax);
        this.t.i();
    }

    public final void c(int i) {
        f fVar;
        AbstractC1361d0 adapter = getAdapter();
        if (adapter == null) {
            if (this.h != -1) {
                this.h = Math.max(i, 0);
                return;
            }
            return;
        }
        if (adapter.getItemCount() <= 0) {
            return;
        }
        int iMin = Math.min(Math.max(i, 0), adapter.getItemCount() - 1);
        int i2 = this.d;
        if ((iMin == i2 && this.l.f == 0) || iMin == i2) {
            return;
        }
        double d = i2;
        this.d = iMin;
        this.t.i();
        d dVar = this.l;
        if (dVar.f != 0) {
            dVar.e();
            c cVar = dVar.g;
            d = cVar.b + cVar.a;
        }
        d dVar2 = this.l;
        dVar2.getClass();
        dVar2.e = 2;
        boolean z = dVar2.i != iMin;
        dVar2.i = iMin;
        dVar2.c(2);
        if (z && (fVar = dVar2.a) != null) {
            fVar.c(iMin);
        }
        double d2 = iMin;
        if (Math.abs(d2 - d) <= 3.0d) {
            this.j.n0(iMin);
            return;
        }
        this.j.k0(d2 > d ? iMin - 3 : iMin + 3);
        l lVar = this.j;
        lVar.post(new androidx.core.provider.a(iMin, lVar));
    }

    @Override // android.view.View
    public final boolean canScrollHorizontally(int i) {
        return this.j.canScrollHorizontally(i);
    }

    @Override // android.view.View
    public final boolean canScrollVertically(int i) {
        return this.j.canScrollVertically(i);
    }

    public final void d() {
        k kVar = this.k;
        if (kVar == null) {
            throw new IllegalStateException("Design assumption violated.");
        }
        View viewG = kVar.g(this.g);
        if (viewG == null) {
            return;
        }
        this.g.getClass();
        int iK = AbstractC1381n0.K(viewG);
        if (iK != this.d && getScrollState() == 0) {
            this.m.c(iK);
        }
        this.e = false;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchRestoreInstanceState(SparseArray sparseArray) {
        Parcelable parcelable = (Parcelable) sparseArray.get(getId());
        if (parcelable instanceof SavedState) {
            int i = ((SavedState) parcelable).a;
            sparseArray.put(this.j.getId(), (Parcelable) sparseArray.get(i));
            sparseArray.remove(i);
        }
        super.dispatchRestoreInstanceState(sparseArray);
        b();
    }

    @Override // android.view.ViewGroup, android.view.View
    public CharSequence getAccessibilityClassName() {
        this.t.getClass();
        this.t.getClass();
        return "androidx.viewpager.widget.ViewPager";
    }

    public AbstractC1361d0 getAdapter() {
        return this.j.getAdapter();
    }

    public int getCurrentItem() {
        return this.d;
    }

    public int getItemDecorationCount() {
        return this.j.getItemDecorationCount();
    }

    public int getOffscreenPageLimit() {
        return this.s;
    }

    public int getOrientation() {
        return this.g.p == 1 ? 1 : 0;
    }

    public int getPageSize() {
        int height;
        int paddingBottom;
        l lVar = this.j;
        if (getOrientation() == 0) {
            height = lVar.getWidth() - lVar.getPaddingLeft();
            paddingBottom = lVar.getPaddingRight();
        } else {
            height = lVar.getHeight() - lVar.getPaddingTop();
            paddingBottom = lVar.getPaddingBottom();
        }
        return height - paddingBottom;
    }

    public int getScrollState() {
        return this.l.f;
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        int itemCount;
        int itemCount2;
        int itemCount3;
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        ViewPager2 viewPager2 = (ViewPager2) this.t.d;
        if (viewPager2.getAdapter() == null) {
            itemCount = 0;
            itemCount2 = 0;
        } else if (viewPager2.getOrientation() == 1) {
            itemCount = viewPager2.getAdapter().getItemCount();
            itemCount2 = 1;
        } else {
            itemCount2 = viewPager2.getAdapter().getItemCount();
            itemCount = 1;
        }
        accessibilityNodeInfo.setCollectionInfo((AccessibilityNodeInfo.CollectionInfo) Q.C(itemCount, itemCount2, 0).a);
        AbstractC1361d0 adapter = viewPager2.getAdapter();
        if (adapter == null || (itemCount3 = adapter.getItemCount()) == 0 || !viewPager2.r) {
            return;
        }
        if (viewPager2.d > 0) {
            accessibilityNodeInfo.addAction(8192);
        }
        if (viewPager2.d < itemCount3 - 1) {
            accessibilityNodeInfo.addAction(4096);
        }
        accessibilityNodeInfo.setScrollable(true);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int measuredWidth = this.j.getMeasuredWidth();
        int measuredHeight = this.j.getMeasuredHeight();
        int paddingLeft = getPaddingLeft();
        Rect rect = this.a;
        rect.left = paddingLeft;
        rect.right = (i3 - i) - getPaddingRight();
        rect.top = getPaddingTop();
        rect.bottom = (i4 - i2) - getPaddingBottom();
        Rect rect2 = this.b;
        Gravity.apply(8388659, measuredWidth, measuredHeight, rect, rect2);
        this.j.layout(rect2.left, rect2.top, rect2.right, rect2.bottom);
        if (this.e) {
            d();
        }
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        measureChild(this.j, i, i2);
        int measuredWidth = this.j.getMeasuredWidth();
        int measuredHeight = this.j.getMeasuredHeight();
        int measuredState = this.j.getMeasuredState();
        int paddingRight = getPaddingRight() + getPaddingLeft() + measuredWidth;
        int paddingBottom = getPaddingBottom() + getPaddingTop() + measuredHeight;
        setMeasuredDimension(View.resolveSizeAndState(Math.max(paddingRight, getSuggestedMinimumWidth()), i, measuredState), View.resolveSizeAndState(Math.max(paddingBottom, getSuggestedMinimumHeight()), i2, measuredState << 16));
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        this.h = savedState.b;
        this.i = savedState.c;
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.a = this.j.getId();
        int i = this.h;
        if (i == -1) {
            i = this.d;
        }
        savedState.b = i;
        Parcelable parcelable = this.i;
        if (parcelable != null) {
            savedState.c = parcelable;
            return savedState;
        }
        this.j.getAdapter();
        return savedState;
    }

    @Override // android.view.ViewGroup
    public final void onViewAdded(View view) {
        throw new IllegalStateException("ViewPager2 does not support direct child views");
    }

    @Override // android.view.View
    public final boolean performAccessibilityAction(int i, Bundle bundle) {
        this.t.getClass();
        if (i != 8192 && i != 4096) {
            return super.performAccessibilityAction(i, bundle);
        }
        n nVar = this.t;
        nVar.getClass();
        if (i != 8192 && i != 4096) {
            throw new IllegalStateException();
        }
        ViewPager2 viewPager2 = (ViewPager2) nVar.d;
        int currentItem = i == 8192 ? viewPager2.getCurrentItem() - 1 : viewPager2.getCurrentItem() + 1;
        if (viewPager2.r) {
            viewPager2.c(currentItem);
        }
        return true;
    }

    public void setAdapter(AbstractC1361d0 abstractC1361d0) {
        AbstractC1361d0 adapter = this.j.getAdapter();
        n nVar = this.t;
        if (adapter != null) {
            adapter.unregisterAdapterDataObserver((e) nVar.c);
        } else {
            nVar.getClass();
        }
        e eVar = this.f;
        if (adapter != null) {
            adapter.unregisterAdapterDataObserver(eVar);
        }
        this.j.setAdapter(abstractC1361d0);
        this.d = 0;
        b();
        n nVar2 = this.t;
        nVar2.i();
        if (abstractC1361d0 != null) {
            abstractC1361d0.registerAdapterDataObserver((e) nVar2.c);
        }
        if (abstractC1361d0 != null) {
            abstractC1361d0.registerAdapterDataObserver(eVar);
        }
    }

    public void setCurrentItem(int i) {
        Object obj = this.n.b;
        c(i);
    }

    @Override // android.view.View
    public void setLayoutDirection(int i) {
        super.setLayoutDirection(i);
        this.t.i();
    }

    public void setOffscreenPageLimit(int i) {
        if (i < 1 && i != -1) {
            throw new IllegalArgumentException("Offscreen page limit must be OFFSCREEN_PAGE_LIMIT_DEFAULT or a number > 0");
        }
        this.s = i;
        this.j.requestLayout();
    }

    public void setOrientation(int i) {
        this.g.k1(i);
        this.t.i();
    }

    public void setPageTransformer(j jVar) {
        if (jVar != null) {
            if (!this.q) {
                this.p = this.j.getItemAnimator();
                this.q = true;
            }
            this.j.setItemAnimator(null);
        } else if (this.q) {
            this.j.setItemAnimator(this.p);
            this.p = null;
            this.q = false;
        }
        this.o.getClass();
        if (jVar == null) {
            return;
        }
        this.o.getClass();
        this.o.getClass();
    }

    public void setUserInputEnabled(boolean z) {
        this.r = z;
        this.t.i();
    }

    public ViewPager2(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.a = new Rect();
        this.b = new Rect();
        this.c = new f();
        this.e = false;
        this.f = new e(this, 0);
        this.h = -1;
        this.p = null;
        this.q = false;
        this.r = true;
        this.s = -1;
        a(context, attributeSet);
    }
}
