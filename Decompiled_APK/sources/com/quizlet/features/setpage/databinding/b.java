package com.quizlet.features.setpage.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public final class b implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QSegmentedControl b;

    public b(ConstraintLayout constraintLayout, QSegmentedControl qSegmentedControl) {
        this.a = constraintLayout;
        this.b = qSegmentedControl;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
