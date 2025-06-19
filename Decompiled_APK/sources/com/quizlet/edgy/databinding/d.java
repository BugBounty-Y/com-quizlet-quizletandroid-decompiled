package com.quizlet.edgy.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class d implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblySecondaryButton b;

    public d(ConstraintLayout constraintLayout, AssemblySecondaryButton assemblySecondaryButton) {
        this.a = constraintLayout;
        this.b = assemblySecondaryButton;
    }

    public static d a(View view) {
        AssemblySecondaryButton assemblySecondaryButton = (AssemblySecondaryButton) AbstractC3375o2.c(R.id.btnAddManually, view);
        if (assemblySecondaryButton != null) {
            return new d((ConstraintLayout) view, assemblySecondaryButton);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.btnAddManually)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
