package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.AutoCompleteTextView;
import android.widget.ScrollView;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes2.dex */
public final class c implements androidx.viewbinding.a {
    public final ScrollView a;
    public final QButton b;
    public final AssemblyInputEditText c;
    public final AutoCompleteTextView d;
    public final AssemblyInputEditText e;
    public final AutoCompleteTextView f;
    public final AssemblyInputLayout g;

    public c(ScrollView scrollView, QButton qButton, AssemblyInputEditText assemblyInputEditText, AutoCompleteTextView autoCompleteTextView, AssemblyInputEditText assemblyInputEditText2, AutoCompleteTextView autoCompleteTextView2, AssemblyInputLayout assemblyInputLayout) {
        this.a = scrollView;
        this.b = qButton;
        this.c = assemblyInputEditText;
        this.d = autoCompleteTextView;
        this.e = assemblyInputEditText2;
        this.f = autoCompleteTextView2;
        this.g = assemblyInputLayout;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
