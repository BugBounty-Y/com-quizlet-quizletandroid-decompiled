package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.ExistingAccountView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;

/* renamed from: com.quizlet.quizletandroid.databinding.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4597a implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final QFormField b;
    public final QFormField c;
    public final ExistingAccountView d;
    public final QTextView e;
    public final AssemblyPrimaryButton f;

    public C4597a(ConstraintLayout constraintLayout, QFormField qFormField, QFormField qFormField2, ExistingAccountView existingAccountView, QTextView qTextView, AssemblyPrimaryButton assemblyPrimaryButton) {
        this.a = constraintLayout;
        this.b = qFormField;
        this.c = qFormField2;
        this.d = existingAccountView;
        this.e = qTextView;
        this.f = assemblyPrimaryButton;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
