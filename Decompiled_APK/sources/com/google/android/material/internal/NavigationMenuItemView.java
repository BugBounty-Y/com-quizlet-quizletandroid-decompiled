package com.google.android.material.internal;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.StateListDrawable;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.CheckedTextView;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.appcompat.view.menu.A;
import androidx.appcompat.widget.C0121y0;
import androidx.appcompat.widget.y1;
import androidx.core.view.V;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class NavigationMenuItemView extends g implements A {
    public static final int[] G = {R.attr.state_checked};
    public FrameLayout A;
    public androidx.appcompat.view.menu.p B;
    public ColorStateList C;
    public boolean D;
    public Drawable E;
    public final androidx.viewpager.widget.e F;
    public int v;
    public boolean w;
    public boolean x;
    public final boolean y;
    public final CheckedTextView z;

    public NavigationMenuItemView(@NonNull Context context) {
        this(context, null);
    }

    private void setActionView(View view) {
        if (view != null) {
            if (this.A == null) {
                this.A = (FrameLayout) ((ViewStub) findViewById(com.quizlet.quizletandroid.R.id.design_menu_item_action_area_stub)).inflate();
            }
            if (view.getParent() != null) {
                ((ViewGroup) view.getParent()).removeView(view);
            }
            this.A.removeAllViews();
            this.A.addView(view);
        }
    }

    @Override // androidx.appcompat.view.menu.A
    public final void d(androidx.appcompat.view.menu.p pVar) throws Resources.NotFoundException {
        StateListDrawable stateListDrawable;
        this.B = pVar;
        int i = pVar.a;
        if (i > 0) {
            setId(i);
        }
        setVisibility(pVar.isVisible() ? 0 : 8);
        if (getBackground() == null) {
            TypedValue typedValue = new TypedValue();
            if (getContext().getTheme().resolveAttribute(com.quizlet.quizletandroid.R.attr.colorControlHighlight, typedValue, true)) {
                stateListDrawable = new StateListDrawable();
                stateListDrawable.addState(G, new ColorDrawable(typedValue.data));
                stateListDrawable.addState(ViewGroup.EMPTY_STATE_SET, new ColorDrawable(0));
            } else {
                stateListDrawable = null;
            }
            WeakHashMap weakHashMap = V.a;
            setBackground(stateListDrawable);
        }
        setCheckable(pVar.isCheckable());
        setChecked(pVar.isChecked());
        setEnabled(pVar.isEnabled());
        setTitle(pVar.e);
        setIcon(pVar.getIcon());
        setActionView(pVar.getActionView());
        setContentDescription(pVar.q);
        y1.a(this, pVar.r);
        androidx.appcompat.view.menu.p pVar2 = this.B;
        CharSequence charSequence = pVar2.e;
        CheckedTextView checkedTextView = this.z;
        if (charSequence == null && pVar2.getIcon() == null && this.B.getActionView() != null) {
            checkedTextView.setVisibility(8);
            FrameLayout frameLayout = this.A;
            if (frameLayout != null) {
                C0121y0 c0121y0 = (C0121y0) frameLayout.getLayoutParams();
                ((LinearLayout.LayoutParams) c0121y0).width = -1;
                this.A.setLayoutParams(c0121y0);
                return;
            }
            return;
        }
        checkedTextView.setVisibility(0);
        FrameLayout frameLayout2 = this.A;
        if (frameLayout2 != null) {
            C0121y0 c0121y02 = (C0121y0) frameLayout2.getLayoutParams();
            ((LinearLayout.LayoutParams) c0121y02).width = -2;
            this.A.setLayoutParams(c0121y02);
        }
    }

    @Override // androidx.appcompat.view.menu.A
    public androidx.appcompat.view.menu.p getItemData() {
        return this.B;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final int[] onCreateDrawableState(int i) {
        int[] iArrOnCreateDrawableState = super.onCreateDrawableState(i + 1);
        androidx.appcompat.view.menu.p pVar = this.B;
        if (pVar != null && pVar.isCheckable() && this.B.isChecked()) {
            View.mergeDrawableStates(iArrOnCreateDrawableState, G);
        }
        return iArrOnCreateDrawableState;
    }

    public void setCheckable(boolean z) {
        refreshDrawableState();
        if (this.x != z) {
            this.x = z;
            this.F.h(this.z, 2048);
        }
    }

    public void setChecked(boolean z) {
        refreshDrawableState();
        CheckedTextView checkedTextView = this.z;
        checkedTextView.setChecked(z);
        checkedTextView.setTypeface(checkedTextView.getTypeface(), (z && this.y) ? 1 : 0);
    }

    public void setHorizontalPadding(int i) {
        setPadding(i, getPaddingTop(), i, getPaddingBottom());
    }

    public void setIcon(Drawable drawable) throws Resources.NotFoundException {
        if (drawable != null) {
            if (this.D) {
                Drawable.ConstantState constantState = drawable.getConstantState();
                if (constantState != null) {
                    drawable = constantState.newDrawable();
                }
                drawable = drawable.mutate();
                drawable.setTintList(this.C);
            }
            int i = this.v;
            drawable.setBounds(0, 0, i, i);
        } else if (this.w) {
            if (this.E == null) {
                Resources resources = getResources();
                Resources.Theme theme = getContext().getTheme();
                ThreadLocal threadLocal = androidx.core.content.res.k.a;
                Drawable drawable2 = resources.getDrawable(com.quizlet.quizletandroid.R.drawable.navigation_empty_icon, theme);
                this.E = drawable2;
                if (drawable2 != null) {
                    int i2 = this.v;
                    drawable2.setBounds(0, 0, i2, i2);
                }
            }
            drawable = this.E;
        }
        this.z.setCompoundDrawablesRelative(drawable, null, null, null);
    }

    public void setIconPadding(int i) {
        this.z.setCompoundDrawablePadding(i);
    }

    public void setIconSize(int i) {
        this.v = i;
    }

    public void setIconTintList(ColorStateList colorStateList) throws Resources.NotFoundException {
        this.C = colorStateList;
        this.D = colorStateList != null;
        androidx.appcompat.view.menu.p pVar = this.B;
        if (pVar != null) {
            setIcon(pVar.getIcon());
        }
    }

    public void setMaxLines(int i) {
        this.z.setMaxLines(i);
    }

    public void setNeedsEmptyIcon(boolean z) {
        this.w = z;
    }

    public void setTextAppearance(int i) {
        this.z.setTextAppearance(i);
    }

    public void setTextColor(ColorStateList colorStateList) {
        this.z.setTextColor(colorStateList);
    }

    public void setTitle(CharSequence charSequence) {
        this.z.setText(charSequence);
    }

    public NavigationMenuItemView(@NonNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.y = true;
        androidx.viewpager.widget.e eVar = new androidx.viewpager.widget.e(this, 5);
        this.F = eVar;
        setOrientation(0);
        LayoutInflater.from(context).inflate(com.quizlet.quizletandroid.R.layout.design_navigation_menu_item, (ViewGroup) this, true);
        setIconSize(context.getResources().getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.design_navigation_icon_size));
        CheckedTextView checkedTextView = (CheckedTextView) findViewById(com.quizlet.quizletandroid.R.id.design_menu_item_text);
        this.z = checkedTextView;
        checkedTextView.setDuplicateParentStateEnabled(true);
        V.o(checkedTextView, eVar);
    }
}
