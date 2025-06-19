package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.common.widgets.EditTextDatePicker;
import com.quizlet.uicommon.ui.common.widgets.QFormField;

/* loaded from: classes3.dex */
public final class G implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final EditTextDatePicker b;
    public final QFormField c;
    public final QTextView d;
    public final QTextView e;
    public final QFormField f;
    public final QButton g;
    public final com.quizlet.assembly.databinding.b h;

    public G(LinearLayout linearLayout, EditTextDatePicker editTextDatePicker, QFormField qFormField, QTextView qTextView, QTextView qTextView2, QFormField qFormField2, QButton qButton, com.quizlet.assembly.databinding.b bVar) {
        this.a = linearLayout;
        this.b = editTextDatePicker;
        this.c = qFormField;
        this.d = qTextView;
        this.e = qTextView2;
        this.f = qFormField2;
        this.g = qButton;
        this.h = bVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
