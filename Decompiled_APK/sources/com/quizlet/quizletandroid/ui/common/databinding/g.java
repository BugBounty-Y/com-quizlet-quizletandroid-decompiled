package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RadioGroup;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public final class g implements androidx.viewbinding.a {
    public final ViewGroup a;
    public final QRadioButton b;
    public final QRadioButton c;
    public final RadioGroup d;
    public final QRadioButton e;

    public g(ViewGroup viewGroup, QRadioButton qRadioButton, QRadioButton qRadioButton2, RadioGroup radioGroup, QRadioButton qRadioButton3) {
        this.a = viewGroup;
        this.b = qRadioButton;
        this.c = qRadioButton2;
        this.d = radioGroup;
        this.e = qRadioButton3;
    }

    public static g a(LayoutInflater layoutInflater, QSegmentedControl qSegmentedControl) {
        layoutInflater.inflate(R.layout.widget_segmented_control, qSegmentedControl);
        int i = R.id.widget_segmented_control_left;
        QRadioButton qRadioButton = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_left, qSegmentedControl);
        if (qRadioButton != null) {
            i = R.id.widget_segmented_control_middle;
            QRadioButton qRadioButton2 = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_middle, qSegmentedControl);
            if (qRadioButton2 != null) {
                i = R.id.widget_segmented_control_radiogroup;
                RadioGroup radioGroup = (RadioGroup) AbstractC3375o2.c(R.id.widget_segmented_control_radiogroup, qSegmentedControl);
                if (radioGroup != null) {
                    i = R.id.widget_segmented_control_right;
                    QRadioButton qRadioButton3 = (QRadioButton) AbstractC3375o2.c(R.id.widget_segmented_control_right, qSegmentedControl);
                    if (qRadioButton3 != null) {
                        return new g(qSegmentedControl, qRadioButton, qRadioButton2, radioGroup, qRadioButton3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(qSegmentedControl.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
