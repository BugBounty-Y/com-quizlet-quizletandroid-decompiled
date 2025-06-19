package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.ViewTreeObserver;
import android.widget.ListAdapter;
import androidx.appcompat.view.menu.ViewTreeObserverOnGlobalLayoutListenerC0067d;

/* loaded from: classes.dex */
public final class O extends G0 implements Q {
    public CharSequence C;
    public L D;
    public final Rect E;
    public int F;
    public final /* synthetic */ AppCompatSpinner G;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public O(AppCompatSpinner appCompatSpinner, Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.G = appCompatSpinner;
        this.E = new Rect();
        this.o = appCompatSpinner;
        this.y = true;
        this.z.setFocusable(true);
        this.p = new M(this, 0);
    }

    @Override // androidx.appcompat.widget.Q
    public final CharSequence e() {
        return this.C;
    }

    @Override // androidx.appcompat.widget.Q
    public final void h(CharSequence charSequence) {
        this.C = charSequence;
    }

    @Override // androidx.appcompat.widget.Q
    public final void l(int i) {
        this.F = i;
    }

    @Override // androidx.appcompat.widget.Q
    public final void m(int i, int i2) {
        ViewTreeObserver viewTreeObserver;
        B b = this.z;
        boolean zIsShowing = b.isShowing();
        s();
        this.z.setInputMethodMode(2);
        f();
        C0113u0 c0113u0 = this.c;
        c0113u0.setChoiceMode(1);
        c0113u0.setTextDirection(i);
        c0113u0.setTextAlignment(i2);
        AppCompatSpinner appCompatSpinner = this.G;
        int selectedItemPosition = appCompatSpinner.getSelectedItemPosition();
        C0113u0 c0113u02 = this.c;
        if (b.isShowing() && c0113u02 != null) {
            c0113u02.setListSelectionHidden(false);
            c0113u02.setSelection(selectedItemPosition);
            if (c0113u02.getChoiceMode() != 0) {
                c0113u02.setItemChecked(selectedItemPosition, true);
            }
        }
        if (zIsShowing || (viewTreeObserver = appCompatSpinner.getViewTreeObserver()) == null) {
            return;
        }
        ViewTreeObserverOnGlobalLayoutListenerC0067d viewTreeObserverOnGlobalLayoutListenerC0067d = new ViewTreeObserverOnGlobalLayoutListenerC0067d(this, 3);
        viewTreeObserver.addOnGlobalLayoutListener(viewTreeObserverOnGlobalLayoutListenerC0067d);
        this.z.setOnDismissListener(new N(this, viewTreeObserverOnGlobalLayoutListenerC0067d));
    }

    @Override // androidx.appcompat.widget.G0, androidx.appcompat.widget.Q
    public final void p(ListAdapter listAdapter) {
        super.p(listAdapter);
        this.D = (L) listAdapter;
    }

    public final void s() {
        int i;
        B b = this.z;
        Drawable background = b.getBackground();
        AppCompatSpinner appCompatSpinner = this.G;
        if (background != null) {
            background.getPadding(appCompatSpinner.h);
            boolean z = C1.a;
            int layoutDirection = appCompatSpinner.getLayoutDirection();
            Rect rect = appCompatSpinner.h;
            i = layoutDirection == 1 ? rect.right : -rect.left;
        } else {
            Rect rect2 = appCompatSpinner.h;
            rect2.right = 0;
            rect2.left = 0;
            i = 0;
        }
        int paddingLeft = appCompatSpinner.getPaddingLeft();
        int paddingRight = appCompatSpinner.getPaddingRight();
        int width = appCompatSpinner.getWidth();
        int i2 = appCompatSpinner.g;
        if (i2 == -2) {
            int iA = appCompatSpinner.a(this.D, b.getBackground());
            int i3 = appCompatSpinner.getContext().getResources().getDisplayMetrics().widthPixels;
            Rect rect3 = appCompatSpinner.h;
            int i4 = (i3 - rect3.left) - rect3.right;
            if (iA > i4) {
                iA = i4;
            }
            r(Math.max(iA, (width - paddingLeft) - paddingRight));
        } else if (i2 == -1) {
            r((width - paddingLeft) - paddingRight);
        } else {
            r(i2);
        }
        boolean z2 = C1.a;
        this.f = appCompatSpinner.getLayoutDirection() == 1 ? (((width - paddingRight) - this.e) - this.F) + i : paddingLeft + this.F + i;
    }
}
