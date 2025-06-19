package com.google.android.material.appbar;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.Menu;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.L;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.Y3;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Collections;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class MaterialToolbar extends Toolbar {
    public static final ImageView.ScaleType[] m1 = {ImageView.ScaleType.MATRIX, ImageView.ScaleType.FIT_XY, ImageView.ScaleType.FIT_START, ImageView.ScaleType.FIT_CENTER, ImageView.ScaleType.FIT_END, ImageView.ScaleType.CENTER, ImageView.ScaleType.CENTER_CROP, ImageView.ScaleType.CENTER_INSIDE};
    public Integer h1;
    public boolean i1;
    public boolean j1;
    public ImageView.ScaleType k1;
    public Boolean l1;

    public MaterialToolbar(@NonNull Context context) {
        this(context, null);
    }

    public ImageView.ScaleType getLogoScaleType() {
        return this.k1;
    }

    public Integer getNavigationIconTint() {
        return this.h1;
    }

    @Override // androidx.appcompat.widget.Toolbar
    public final void m(int i) {
        Menu menu = getMenu();
        boolean z = menu instanceof androidx.appcompat.view.menu.n;
        if (z) {
            ((androidx.appcompat.view.menu.n) menu).w();
        }
        super.m(i);
        if (z) {
            ((androidx.appcompat.view.menu.n) menu).v();
        }
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        AbstractC3466h4.c(this);
    }

    @Override // androidx.appcompat.widget.Toolbar, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        ImageView imageView;
        Drawable drawable;
        super.onLayout(z, i, i2, i3, i4);
        int i5 = 0;
        ImageView imageView2 = null;
        if (this.i1 || this.j1) {
            ArrayList arrayListJ = p.j(this, getTitle());
            boolean zIsEmpty = arrayListJ.isEmpty();
            androidx.constraintlayout.core.e eVar = p.c;
            TextView textView = zIsEmpty ? null : (TextView) Collections.min(arrayListJ, eVar);
            ArrayList arrayListJ2 = p.j(this, getSubtitle());
            TextView textView2 = arrayListJ2.isEmpty() ? null : (TextView) Collections.max(arrayListJ2, eVar);
            if (textView != null || textView2 != null) {
                int measuredWidth = getMeasuredWidth();
                int i6 = measuredWidth / 2;
                int paddingLeft = getPaddingLeft();
                int paddingRight = measuredWidth - getPaddingRight();
                for (int i7 = 0; i7 < getChildCount(); i7++) {
                    View childAt = getChildAt(i7);
                    if (childAt.getVisibility() != 8 && childAt != textView && childAt != textView2) {
                        if (childAt.getRight() < i6 && childAt.getRight() > paddingLeft) {
                            paddingLeft = childAt.getRight();
                        }
                        if (childAt.getLeft() > i6 && childAt.getLeft() < paddingRight) {
                            paddingRight = childAt.getLeft();
                        }
                    }
                }
                Pair pair = new Pair(Integer.valueOf(paddingLeft), Integer.valueOf(paddingRight));
                if (this.i1 && textView != null) {
                    x(textView, pair);
                }
                if (this.j1 && textView2 != null) {
                    x(textView2, pair);
                }
            }
        }
        Drawable logo = getLogo();
        if (logo != null) {
            while (true) {
                if (i5 >= getChildCount()) {
                    break;
                }
                View childAt2 = getChildAt(i5);
                if ((childAt2 instanceof ImageView) && (drawable = (imageView = (ImageView) childAt2).getDrawable()) != null && drawable.getConstantState() != null && drawable.getConstantState().equals(logo.getConstantState())) {
                    imageView2 = imageView;
                    break;
                }
                i5++;
            }
        }
        if (imageView2 != null) {
            Boolean bool = this.l1;
            if (bool != null) {
                imageView2.setAdjustViewBounds(bool.booleanValue());
            }
            ImageView.ScaleType scaleType = this.k1;
            if (scaleType != null) {
                imageView2.setScaleType(scaleType);
            }
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

    public void setLogoAdjustViewBounds(boolean z) {
        Boolean bool = this.l1;
        if (bool == null || bool.booleanValue() != z) {
            this.l1 = Boolean.valueOf(z);
            requestLayout();
        }
    }

    public void setLogoScaleType(@NonNull ImageView.ScaleType scaleType) {
        if (this.k1 != scaleType) {
            this.k1 = scaleType;
            requestLayout();
        }
    }

    @Override // androidx.appcompat.widget.Toolbar
    public void setNavigationIcon(Drawable drawable) {
        if (drawable != null && this.h1 != null) {
            drawable = drawable.mutate();
            drawable.setTint(this.h1.intValue());
        }
        super.setNavigationIcon(drawable);
    }

    public void setNavigationIconTint(int i) {
        this.h1 = Integer.valueOf(i);
        Drawable navigationIcon = getNavigationIcon();
        if (navigationIcon != null) {
            setNavigationIcon(navigationIcon);
        }
    }

    public void setSubtitleCentered(boolean z) {
        if (this.j1 != z) {
            this.j1 = z;
            requestLayout();
        }
    }

    public void setTitleCentered(boolean z) {
        if (this.i1 != z) {
            this.i1 = z;
            requestLayout();
        }
    }

    public final void x(TextView textView, Pair pair) {
        int measuredWidth = getMeasuredWidth();
        int measuredWidth2 = textView.getMeasuredWidth();
        int i = (measuredWidth / 2) - (measuredWidth2 / 2);
        int i2 = measuredWidth2 + i;
        int iMax = Math.max(Math.max(((Integer) pair.first).intValue() - i, 0), Math.max(i2 - ((Integer) pair.second).intValue(), 0));
        if (iMax > 0) {
            i += iMax;
            i2 -= iMax;
            textView.measure(View.MeasureSpec.makeMeasureSpec(i2 - i, 1073741824), textView.getMeasuredHeightAndState());
        }
        textView.layout(i, textView.getTop(), i2, textView.getBottom());
    }

    public MaterialToolbar(@NonNull Context context, AttributeSet attributeSet) {
        super(com.google.android.material.theme.overlay.a.a(context, attributeSet, R.attr.toolbarStyle, R.style.Widget_MaterialComponents_Toolbar), attributeSet, R.attr.toolbarStyle);
        Context context2 = getContext();
        TypedArray typedArrayL = p.l(context2, attributeSet, com.google.android.material.a.F, R.attr.toolbarStyle, R.style.Widget_MaterialComponents_Toolbar, new int[0]);
        if (typedArrayL.hasValue(2)) {
            setNavigationIconTint(typedArrayL.getColor(2, -1));
        }
        this.i1 = typedArrayL.getBoolean(4, false);
        this.j1 = typedArrayL.getBoolean(3, false);
        int i = typedArrayL.getInt(1, -1);
        if (i >= 0) {
            ImageView.ScaleType[] scaleTypeArr = m1;
            if (i < scaleTypeArr.length) {
                this.k1 = scaleTypeArr[i];
            }
        }
        if (typedArrayL.hasValue(0)) {
            this.l1 = Boolean.valueOf(typedArrayL.getBoolean(0, false));
        }
        typedArrayL.recycle();
        Drawable background = getBackground();
        ColorStateList colorStateListValueOf = background == null ? ColorStateList.valueOf(0) : Y3.j(background);
        if (colorStateListValueOf != null) {
            com.google.android.material.shape.g gVar = new com.google.android.material.shape.g();
            gVar.m(colorStateListValueOf);
            gVar.k(context2);
            WeakHashMap weakHashMap = V.a;
            gVar.l(L.e(this));
            setBackground(gVar);
        }
    }
}
