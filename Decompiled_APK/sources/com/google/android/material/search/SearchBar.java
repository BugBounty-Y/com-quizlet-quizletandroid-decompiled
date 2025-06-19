package com.google.android.material.search;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.view.menu.ViewOnAttachStateChangeListenerC0068e;
import androidx.appcompat.view.menu.n;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.customview.view.AbsSavedState;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class SearchBar extends Toolbar {
    public static final /* synthetic */ int w1 = 0;
    public final TextView h1;
    public final boolean i1;
    public final boolean j1;
    public final u k1;
    public final Drawable l1;
    public final boolean m1;
    public final boolean n1;
    public View o1;
    public final Integer p1;
    public Drawable q1;
    public int r1;
    public boolean s1;
    public final com.google.android.material.shape.g t1;
    public final AccessibilityManager u1;
    public final a v1;

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new b();
        public String c;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readString();
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeString(this.c);
        }
    }

    public SearchBar(@NonNull Context context) {
        super(com.google.android.material.theme.overlay.a.a(context, null, R.attr.materialSearchBarStyle, R.style.Widget_Material3_SearchBar), null, R.attr.materialSearchBarStyle);
        this.r1 = -1;
        this.v1 = new a(this, 0);
        Context context2 = getContext();
        Drawable drawableF = com.facebook.appevents.g.f(context2, getDefaultNavigationIconResource());
        this.l1 = drawableF;
        u uVar = new u(18);
        new LinkedHashSet();
        new LinkedHashSet();
        new LinkedHashSet();
        this.k1 = uVar;
        TypedArray typedArrayL = p.l(context2, null, com.google.android.material.a.I, R.attr.materialSearchBarStyle, R.style.Widget_Material3_SearchBar, new int[0]);
        com.google.android.material.shape.j jVarA = com.google.android.material.shape.j.b(context2, null, R.attr.materialSearchBarStyle, R.style.Widget_Material3_SearchBar).a();
        int color = typedArrayL.getColor(3, 0);
        float dimension = typedArrayL.getDimension(6, DefinitionKt.NO_Float_VALUE);
        this.j1 = typedArrayL.getBoolean(4, true);
        this.s1 = typedArrayL.getBoolean(5, true);
        boolean z = typedArrayL.getBoolean(8, false);
        this.n1 = typedArrayL.getBoolean(7, false);
        this.m1 = typedArrayL.getBoolean(12, true);
        if (typedArrayL.hasValue(9)) {
            this.p1 = Integer.valueOf(typedArrayL.getColor(9, -1));
        }
        int resourceId = typedArrayL.getResourceId(0, -1);
        String string = typedArrayL.getString(1);
        String string2 = typedArrayL.getString(2);
        float dimension2 = typedArrayL.getDimension(11, -1.0f);
        int color2 = typedArrayL.getColor(10, 0);
        typedArrayL.recycle();
        if (!z) {
            setNavigationIcon(getNavigationIcon() != null ? getNavigationIcon() : drawableF);
            setNavigationIconDecorative(true);
        }
        setClickable(true);
        setFocusable(true);
        LayoutInflater.from(context2).inflate(R.layout.mtrl_search_bar, this);
        this.i1 = true;
        TextView textView = (TextView) findViewById(R.id.open_search_bar_text_view);
        this.h1 = textView;
        L.k(this, dimension);
        if (resourceId != -1) {
            textView.setTextAppearance(resourceId);
        }
        setText(string);
        setHint(string2);
        if (getNavigationIcon() == null) {
            ((ViewGroup.MarginLayoutParams) textView.getLayoutParams()).setMarginStart(getResources().getDimensionPixelSize(R.dimen.m3_searchbar_text_margin_start_no_navigation_icon));
        }
        com.google.android.material.shape.g gVar = new com.google.android.material.shape.g(jVarA);
        this.t1 = gVar;
        gVar.k(getContext());
        this.t1.l(dimension);
        if (dimension2 >= DefinitionKt.NO_Float_VALUE) {
            com.google.android.material.shape.g gVar2 = this.t1;
            gVar2.a.j = dimension2;
            gVar2.invalidateSelf();
            gVar2.r(ColorStateList.valueOf(color2));
        }
        int iB = X3.b(R.attr.colorControlHighlight, this);
        this.t1.m(ColorStateList.valueOf(color));
        ColorStateList colorStateListValueOf = ColorStateList.valueOf(iB);
        com.google.android.material.shape.g gVar3 = this.t1;
        RippleDrawable rippleDrawable = new RippleDrawable(colorStateListValueOf, gVar3, gVar3);
        WeakHashMap weakHashMap = V.a;
        setBackground(rippleDrawable);
        AccessibilityManager accessibilityManager = (AccessibilityManager) getContext().getSystemService("accessibility");
        this.u1 = accessibilityManager;
        if (accessibilityManager != null) {
            if (accessibilityManager.isEnabled() && accessibilityManager.isTouchExplorationEnabled()) {
                setFocusableInTouchMode(true);
            }
            addOnAttachStateChangeListener(new ViewOnAttachStateChangeListenerC0068e(this, 5));
        }
    }

    private void setNavigationIconDecorative(boolean z) {
        ImageButton imageButtonI = p.i(this);
        if (imageButtonI == null) {
            return;
        }
        imageButtonI.setClickable(!z);
        imageButtonI.setFocusable(!z);
        Drawable background = imageButtonI.getBackground();
        if (background != null) {
            this.q1 = background;
        }
        imageButtonI.setBackgroundDrawable(z ? null : this.q1);
        x();
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        if (this.i1 && this.o1 == null && !(view instanceof ActionMenuView)) {
            this.o1 = view;
            view.setAlpha(DefinitionKt.NO_Float_VALUE);
        }
        super.addView(view, i, layoutParams);
    }

    public View getCenterView() {
        return this.o1;
    }

    public float getCompatElevation() {
        com.google.android.material.shape.g gVar = this.t1;
        if (gVar != null) {
            return gVar.a.m;
        }
        WeakHashMap weakHashMap = V.a;
        return L.e(this);
    }

    public float getCornerSize() {
        return this.t1.i();
    }

    public int getDefaultMarginVerticalResource() {
        return R.dimen.m3_searchbar_margin_vertical;
    }

    public int getDefaultNavigationIconResource() {
        return R.drawable.ic_search_black_24;
    }

    public CharSequence getHint() {
        return this.h1.getHint();
    }

    public int getMenuResId() {
        return this.r1;
    }

    public int getStrokeColor() {
        return this.t1.a.d.getDefaultColor();
    }

    public float getStrokeWidth() {
        return this.t1.a.j;
    }

    @NonNull
    public CharSequence getText() {
        return this.h1.getText();
    }

    @NonNull
    public TextView getTextView() {
        return this.h1;
    }

    @Override // androidx.appcompat.widget.Toolbar
    public final void m(int i) {
        Menu menu = getMenu();
        boolean z = menu instanceof n;
        if (z) {
            ((n) menu).w();
        }
        super.m(i);
        this.r1 = i;
        if (z) {
            ((n) menu).v();
        }
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() throws Resources.NotFoundException {
        super.onAttachedToWindow();
        AbstractC3466h4.b(this, this.t1);
        if (this.j1 && (getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) {
            Resources resources = getResources();
            int dimensionPixelSize = resources.getDimensionPixelSize(R.dimen.m3_searchbar_margin_horizontal);
            int dimensionPixelSize2 = resources.getDimensionPixelSize(getDefaultMarginVerticalResource());
            ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) getLayoutParams();
            int i = marginLayoutParams.leftMargin;
            if (i == 0) {
                i = dimensionPixelSize;
            }
            marginLayoutParams.leftMargin = i;
            int i2 = marginLayoutParams.topMargin;
            if (i2 == 0) {
                i2 = dimensionPixelSize2;
            }
            marginLayoutParams.topMargin = i2;
            int i3 = marginLayoutParams.rightMargin;
            if (i3 != 0) {
                dimensionPixelSize = i3;
            }
            marginLayoutParams.rightMargin = dimensionPixelSize;
            int i4 = marginLayoutParams.bottomMargin;
            if (i4 != 0) {
                dimensionPixelSize2 = i4;
            }
            marginLayoutParams.bottomMargin = dimensionPixelSize2;
        }
        y();
    }

    @Override // android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
        accessibilityNodeInfo.setClassName(EditText.class.getCanonicalName());
        accessibilityNodeInfo.setEditable(isEnabled());
        CharSequence text = getText();
        boolean zIsEmpty = TextUtils.isEmpty(text);
        accessibilityNodeInfo.setHintText(getHint());
        accessibilityNodeInfo.setShowingHintText(zIsEmpty);
        if (zIsEmpty) {
            text = getHint();
        }
        accessibilityNodeInfo.setText(text);
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        View view = this.o1;
        if (view != null) {
            int measuredWidth = view.getMeasuredWidth();
            int measuredWidth2 = (getMeasuredWidth() / 2) - (measuredWidth / 2);
            int i5 = measuredWidth + measuredWidth2;
            int measuredHeight = this.o1.getMeasuredHeight();
            int measuredHeight2 = (getMeasuredHeight() / 2) - (measuredHeight / 2);
            int i6 = measuredHeight + measuredHeight2;
            View view2 = this.o1;
            WeakHashMap weakHashMap = V.a;
            if (getLayoutDirection() == 1) {
                view2.layout(getMeasuredWidth() - i5, measuredHeight2, getMeasuredWidth() - measuredWidth2, i6);
            } else {
                view2.layout(measuredWidth2, measuredHeight2, i5, i6);
            }
        }
        x();
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        View view = this.o1;
        if (view != null) {
            view.measure(i, i2);
        }
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        setText(savedState.c);
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        CharSequence text = getText();
        savedState.c = text == null ? null : text.toString();
        return savedState;
    }

    public void setCenterView(View view) {
        View view2 = this.o1;
        if (view2 != null) {
            removeView(view2);
            this.o1 = null;
        }
        if (view != null) {
            addView(view);
        }
    }

    public void setDefaultScrollFlagsEnabled(boolean z) {
        this.s1 = z;
        y();
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        com.google.android.material.shape.g gVar = this.t1;
        if (gVar != null) {
            gVar.l(f);
        }
    }

    public void setHint(CharSequence charSequence) {
        this.h1.setHint(charSequence);
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setNavigationIcon(Drawable drawable) {
        int iB;
        if (this.m1 && drawable != null) {
            Integer num = this.p1;
            if (num != null) {
                iB = num.intValue();
            } else {
                iB = X3.b(drawable == this.l1 ? R.attr.colorOnSurfaceVariant : R.attr.colorOnSurface, this);
            }
            drawable = drawable.mutate();
            drawable.setTint(iB);
        }
        super.setNavigationIcon(drawable);
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setNavigationOnClickListener(View.OnClickListener onClickListener) {
        if (this.n1) {
            return;
        }
        super.setNavigationOnClickListener(onClickListener);
        setNavigationIconDecorative(onClickListener == null);
    }

    public void setOnLoadAnimationFadeInEnabled(boolean z) {
        this.k1.getClass();
    }

    public void setStrokeColor(int i) {
        if (getStrokeColor() != i) {
            this.t1.r(ColorStateList.valueOf(i));
        }
    }

    public void setStrokeWidth(float f) {
        if (getStrokeWidth() != f) {
            com.google.android.material.shape.g gVar = this.t1;
            gVar.a.j = f;
            gVar.invalidateSelf();
        }
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setSubtitle(CharSequence charSequence) {
    }

    public void setText(CharSequence charSequence) {
        this.h1.setText(charSequence);
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setTitle(CharSequence charSequence) {
    }

    public final void x() {
        if (Build.VERSION.SDK_INT < 34) {
            return;
        }
        boolean z = getLayoutDirection() == 1;
        ImageButton imageButtonI = p.i(this);
        int width = (imageButtonI == null || !imageButtonI.isClickable()) ? 0 : z ? getWidth() - imageButtonI.getLeft() : imageButtonI.getRight();
        ActionMenuView actionMenuViewH = p.h(this);
        int right = actionMenuViewH != null ? z ? actionMenuViewH.getRight() : getWidth() - actionMenuViewH.getLeft() : 0;
        float f = -(z ? right : width);
        if (!z) {
            width = right;
        }
        setHandwritingBoundsOffsets(f, DefinitionKt.NO_Float_VALUE, -width, DefinitionKt.NO_Float_VALUE);
    }

    public final void y() {
        if (getLayoutParams() instanceof com.google.android.material.appbar.e) {
            com.google.android.material.appbar.e eVar = (com.google.android.material.appbar.e) getLayoutParams();
            if (this.s1) {
                if (eVar.a == 0) {
                    eVar.a = 53;
                }
            } else if (eVar.a == 53) {
                eVar.a = 0;
            }
        }
    }

    public static class ScrollingViewBehavior extends AppBarLayout.ScrollingViewBehavior {
        public boolean g;

        public ScrollingViewBehavior() {
            this.g = false;
        }

        @Override // com.google.android.material.appbar.AppBarLayout.ScrollingViewBehavior, androidx.coordinatorlayout.widget.b
        public final boolean h(CoordinatorLayout coordinatorLayout, View view, View view2) {
            super.h(coordinatorLayout, view, view2);
            if (!this.g && (view2 instanceof AppBarLayout)) {
                this.g = true;
                AppBarLayout appBarLayout = (AppBarLayout) view2;
                appBarLayout.setBackgroundColor(0);
                appBarLayout.setTargetElevation(DefinitionKt.NO_Float_VALUE);
            }
            return false;
        }

        public ScrollingViewBehavior(@NonNull Context context, AttributeSet attributeSet) {
            super(context, attributeSet);
            this.g = false;
        }
    }

    public void setHint(int i) {
        this.h1.setHint(i);
    }

    public void setText(int i) {
        this.h1.setText(i);
    }
}
