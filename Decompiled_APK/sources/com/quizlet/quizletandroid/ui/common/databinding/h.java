package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.View;
import android.widget.RadioGroup;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public final class h implements androidx.viewbinding.a {
    public final QSegmentedControl a;
    public final QRadioButton b;
    public final QRadioButton c;
    public final RadioGroup d;
    public final QRadioButton e;

    public h(QSegmentedControl qSegmentedControl, QRadioButton qRadioButton, QRadioButton qRadioButton2, RadioGroup radioGroup, QRadioButton qRadioButton3) {
        this.a = qSegmentedControl;
        this.b = qRadioButton;
        this.c = qRadioButton2;
        this.d = radioGroup;
        this.e = qRadioButton3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
