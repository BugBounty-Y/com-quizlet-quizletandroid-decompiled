package com.quizlet.explanations.databinding;

import android.view.View;
import android.widget.RadioGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.assembly.widgets.input.AssemblyInputLayout;

/* loaded from: classes2.dex */
public final class j implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblySecondaryButton b;
    public final RadioGroup c;
    public final AssemblyInputLayout d;
    public final AssemblyPrimaryButton e;

    public j(ConstraintLayout constraintLayout, AssemblySecondaryButton assemblySecondaryButton, RadioGroup radioGroup, AssemblyInputLayout assemblyInputLayout, AssemblyPrimaryButton assemblyPrimaryButton) {
        this.a = constraintLayout;
        this.b = assemblySecondaryButton;
        this.c = radioGroup;
        this.d = assemblyInputLayout;
        this.e = assemblyPrimaryButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
