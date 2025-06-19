package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;

/* loaded from: classes2.dex */
public final class b implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblyPrimaryButton b;
    public final TextView c;
    public final ProgressBar d;
    public final RecyclerView e;
    public final AssemblyInputEditText f;
    public final AssemblyInputLayout g;
    public final AssemblyInputEditText h;
    public final AssemblyInputLayout i;

    public b(ConstraintLayout constraintLayout, AssemblyPrimaryButton assemblyPrimaryButton, TextView textView, ProgressBar progressBar, RecyclerView recyclerView, AssemblyInputEditText assemblyInputEditText, AssemblyInputLayout assemblyInputLayout, AssemblyInputEditText assemblyInputEditText2, AssemblyInputLayout assemblyInputLayout2) {
        this.a = constraintLayout;
        this.b = assemblyPrimaryButton;
        this.c = textView;
        this.d = progressBar;
        this.e = recyclerView;
        this.f = assemblyInputEditText;
        this.g = assemblyInputLayout;
        this.h = assemblyInputEditText2;
        this.i = assemblyInputLayout2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
