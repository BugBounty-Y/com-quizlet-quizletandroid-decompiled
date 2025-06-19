package com.quizlet.login.databinding;

import android.view.View;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;

/* loaded from: classes3.dex */
public final class a implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblyInputEditText b;
    public final AssemblyInputLayout c;
    public final TextView d;
    public final AssemblyInputEditText e;
    public final AssemblyInputLayout f;
    public final AssemblyPrimaryButton g;
    public final TextView h;

    public a(ConstraintLayout constraintLayout, AssemblyInputEditText assemblyInputEditText, AssemblyInputLayout assemblyInputLayout, TextView textView, AssemblyInputEditText assemblyInputEditText2, AssemblyInputLayout assemblyInputLayout2, AssemblyPrimaryButton assemblyPrimaryButton, TextView textView2) {
        this.a = constraintLayout;
        this.b = assemblyInputEditText;
        this.c = assemblyInputLayout;
        this.d = textView;
        this.e = assemblyInputEditText2;
        this.f = assemblyInputLayout2;
        this.g = assemblyPrimaryButton;
        this.h = textView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
