package com.quizlet.quizletandroid.ui.setcreation.scrolling;

import android.util.DisplayMetrics;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.C1383o0;
import androidx.recyclerview.widget.S;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QFormField;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends S {
    public Integer q;
    public float r;
    public int s;

    @Override // androidx.recyclerview.widget.S
    public final int c(View view, int i) {
        Intrinsics.checkNotNullParameter(view, "view");
        Integer num = this.q;
        View viewFindViewById = num != null ? view.findViewById(num.intValue()) : null;
        if (viewFindViewById == null || !(viewFindViewById instanceof QFormField)) {
            return super.c(view, i);
        }
        AbstractC1381n0 abstractC1381n0 = this.c;
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        Intrinsics.e(layoutParams, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView.LayoutParams");
        QFormField qFormField = (QFormField) viewFindViewById;
        ViewGroup.LayoutParams layoutParams2 = qFormField.getLayoutParams();
        Intrinsics.e(layoutParams2, "null cannot be cast to non-null type android.widget.LinearLayout.LayoutParams");
        LinearLayout.LayoutParams layoutParams3 = (LinearLayout.LayoutParams) layoutParams2;
        int top = qFormField.getTop() - layoutParams3.topMargin;
        int bottom = qFormField.getBottom() + layoutParams3.bottomMargin;
        Intrinsics.d(abstractC1381n0);
        int iE = AbstractC1381n0.E(view) - ((ViewGroup.MarginLayoutParams) ((C1383o0) layoutParams)).topMargin;
        int iJ = abstractC1381n0.J();
        int iG = abstractC1381n0.o - abstractC1381n0.G();
        int dimension = (int) view.getContext().getResources().getDimension(R.dimen.focus_form_field_vertical_offset);
        int i2 = iG - iJ;
        return bottom - top > i2 ? a(iE, iE + bottom, iJ, iG, i) - dimension : a(iE, iE + top, iJ, iG, i) - (i2 - dimension);
    }

    @Override // androidx.recyclerview.widget.S
    public final float d(DisplayMetrics displayMetrics) {
        Intrinsics.checkNotNullParameter(displayMetrics, "displayMetrics");
        return this.r / this.s;
    }

    @Override // androidx.recyclerview.widget.S
    public final int h() {
        return 1;
    }
}
