package com.google.android.material.chip;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityNodeInfo;
import androidx.annotation.NonNull;
import androidx.appcompat.app.Q;
import androidx.camera.camera2.internal.m0;
import androidx.core.view.V;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class j extends com.google.android.material.internal.f {
    public int e;
    public int f;
    public i g;
    public final m0 h;
    public final int i;
    public final androidx.core.splashscreen.a j;

    public j(Context context) {
        super(com.google.android.material.theme.overlay.a.a(context, null, R.attr.chipGroupStyle, R.style.Widget_MaterialComponents_ChipGroup), R.attr.chipGroupStyle);
        m0 m0Var = new m0(4);
        this.h = m0Var;
        androidx.core.splashscreen.a aVar = new androidx.core.splashscreen.a(this);
        this.j = aVar;
        TypedArray typedArrayL = p.l(getContext(), null, com.google.android.material.a.i, R.attr.chipGroupStyle, R.style.Widget_MaterialComponents_ChipGroup, new int[0]);
        int dimensionPixelOffset = typedArrayL.getDimensionPixelOffset(1, 0);
        setChipSpacingHorizontal(typedArrayL.getDimensionPixelOffset(2, dimensionPixelOffset));
        setChipSpacingVertical(typedArrayL.getDimensionPixelOffset(3, dimensionPixelOffset));
        setSingleLine(typedArrayL.getBoolean(5, false));
        setSingleSelection(typedArrayL.getBoolean(6, false));
        setSelectionRequired(typedArrayL.getBoolean(4, false));
        this.i = typedArrayL.getResourceId(0, -1);
        typedArrayL.recycle();
        m0Var.e = new androidx.webkit.internal.p(this, 22);
        super.setOnHierarchyChangeListener(aVar);
        WeakHashMap weakHashMap = V.a;
        setImportantForAccessibility(1);
    }

    private int getVisibleChipCount() {
        int i = 0;
        for (int i2 = 0; i2 < getChildCount(); i2++) {
            if ((getChildAt(i2) instanceof Chip) && getChildAt(i2).getVisibility() == 0) {
                i++;
            }
        }
        return i;
    }

    @Override // com.google.android.material.internal.f
    public final boolean a() {
        return this.c;
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return super.checkLayoutParams(layoutParams) && (layoutParams instanceof g);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        return new g(-2, -2);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new g(getContext(), attributeSet);
    }

    public int getCheckedChipId() {
        return this.h.c();
    }

    @NonNull
    public List<Integer> getCheckedChipIds() {
        return this.h.b(this);
    }

    public int getChipSpacingHorizontal() {
        return this.e;
    }

    public int getChipSpacingVertical() {
        return this.f;
    }

    @Override // android.view.View
    public final void onFinishInflate() {
        super.onFinishInflate();
        int i = this.i;
        if (i != -1) {
            m0 m0Var = this.h;
            com.google.android.material.internal.i iVar = (com.google.android.material.internal.i) ((HashMap) m0Var.c).get(Integer.valueOf(i));
            if (iVar != null && m0Var.a(iVar)) {
                m0Var.d();
            }
        }
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setCollectionInfo((AccessibilityNodeInfo.CollectionInfo) Q.C(getRowCount(), this.c ? getVisibleChipCount() : -1, this.h.a ? 1 : 2).a);
    }

    public void setChipSpacing(int i) {
        setChipSpacingHorizontal(i);
        setChipSpacingVertical(i);
    }

    public void setChipSpacingHorizontal(int i) {
        if (this.e != i) {
            this.e = i;
            setItemSpacing(i);
            requestLayout();
        }
    }

    public void setChipSpacingHorizontalResource(int i) {
        setChipSpacingHorizontal(getResources().getDimensionPixelOffset(i));
    }

    public void setChipSpacingResource(int i) {
        setChipSpacing(getResources().getDimensionPixelOffset(i));
    }

    public void setChipSpacingVertical(int i) {
        if (this.f != i) {
            this.f = i;
            setLineSpacing(i);
            requestLayout();
        }
    }

    public void setChipSpacingVerticalResource(int i) {
        setChipSpacingVertical(getResources().getDimensionPixelOffset(i));
    }

    @Deprecated
    public void setDividerDrawableHorizontal(Drawable drawable) {
        throw new UnsupportedOperationException("Changing divider drawables have no effect. ChipGroup do not use divider drawables as spacing.");
    }

    @Deprecated
    public void setDividerDrawableVertical(Drawable drawable) {
        throw new UnsupportedOperationException("Changing divider drawables have no effect. ChipGroup do not use divider drawables as spacing.");
    }

    @Deprecated
    public void setFlexWrap(int i) {
        throw new UnsupportedOperationException("Changing flex wrap not allowed. ChipGroup exposes a singleLine attribute instead.");
    }

    @Deprecated
    public void setOnCheckedChangeListener(h hVar) {
        if (hVar == null) {
            setOnCheckedStateChangeListener(null);
        } else {
            setOnCheckedStateChangeListener(new com.airbnb.lottie.network.c(this, 24));
        }
    }

    public void setOnCheckedStateChangeListener(i iVar) {
        this.g = iVar;
    }

    @Override // android.view.ViewGroup
    public void setOnHierarchyChangeListener(ViewGroup.OnHierarchyChangeListener onHierarchyChangeListener) {
        this.j.b = onHierarchyChangeListener;
    }

    public void setSelectionRequired(boolean z) {
        this.h.b = z;
    }

    @Deprecated
    public void setShowDividerHorizontal(int i) {
        throw new UnsupportedOperationException("Changing divider modes has no effect. ChipGroup do not use divider drawables as spacing.");
    }

    @Deprecated
    public void setShowDividerVertical(int i) {
        throw new UnsupportedOperationException("Changing divider modes has no effect. ChipGroup do not use divider drawables as spacing.");
    }

    @Override // com.google.android.material.internal.f
    public void setSingleLine(boolean z) {
        super.setSingleLine(z);
    }

    public void setSingleSelection(boolean z) {
        m0 m0Var = this.h;
        if (m0Var.a != z) {
            m0Var.a = z;
            boolean zIsEmpty = ((HashSet) m0Var.d).isEmpty();
            Iterator it2 = ((HashMap) m0Var.c).values().iterator();
            while (it2.hasNext()) {
                m0Var.e((com.google.android.material.internal.i) it2.next(), false);
            }
            if (zIsEmpty) {
                return;
            }
            m0Var.d();
        }
    }

    public void setSingleLine(int i) {
        setSingleLine(getResources().getBoolean(i));
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return new g(layoutParams);
    }

    public void setSingleSelection(int i) {
        setSingleSelection(getResources().getBoolean(i));
    }
}
