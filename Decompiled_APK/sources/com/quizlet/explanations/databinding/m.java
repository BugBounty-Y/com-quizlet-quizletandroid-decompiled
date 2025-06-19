package com.quizlet.explanations.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;

/* loaded from: classes2.dex */
public final class m implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblyPrimaryButton b;

    public m(ConstraintLayout constraintLayout, AssemblyPrimaryButton assemblyPrimaryButton) {
        this.a = constraintLayout;
        this.b = assemblyPrimaryButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
