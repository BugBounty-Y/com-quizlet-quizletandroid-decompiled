package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;

/* loaded from: classes2.dex */
public final class r implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblySecondaryButton b;
    public final AssemblySecondaryButton c;

    public r(ConstraintLayout constraintLayout, AssemblySecondaryButton assemblySecondaryButton, AssemblySecondaryButton assemblySecondaryButton2) {
        this.a = constraintLayout;
        this.b = assemblySecondaryButton;
        this.c = assemblySecondaryButton2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
