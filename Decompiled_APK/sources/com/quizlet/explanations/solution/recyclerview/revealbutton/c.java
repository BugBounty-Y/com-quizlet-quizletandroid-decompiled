package com.quizlet.explanations.solution.recyclerview.revealbutton;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.braze.ui.inappmessage.d;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.explanations.databinding.u;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends com.quizlet.baserecyclerview.c {
    @Override // com.quizlet.baserecyclerview.c
    public final void c(Object obj) {
        b item = (b) obj;
        Intrinsics.checkNotNullParameter(item, "item");
        ((u) e()).b.setOnClickListener(new d(item, 19));
    }

    @Override // com.quizlet.baserecyclerview.c
    public final androidx.viewbinding.a d() {
        View view = this.itemView;
        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.showAllStepsButton, view);
        if (assemblyPrimaryButton == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.showAllStepsButton)));
        }
        u uVar = new u((ConstraintLayout) view, assemblyPrimaryButton);
        Intrinsics.checkNotNullExpressionValue(uVar, "bind(...)");
        return uVar;
    }
}
