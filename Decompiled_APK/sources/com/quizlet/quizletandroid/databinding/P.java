package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.uicommon.ui.common.widgets.QFormField;

/* loaded from: classes3.dex */
public final class P implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QFormField b;
    public final AssemblySecondaryButton c;
    public final AssemblyPrimaryButton d;

    public P(ConstraintLayout constraintLayout, QFormField qFormField, AssemblySecondaryButton assemblySecondaryButton, AssemblyPrimaryButton assemblyPrimaryButton) {
        this.a = constraintLayout;
        this.b = qFormField;
        this.c = assemblySecondaryButton;
        this.d = assemblyPrimaryButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
