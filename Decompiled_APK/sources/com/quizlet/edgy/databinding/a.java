package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.ScrollView;
import com.quizlet.assembly.widgets.input.AssemblyInputEditText;
import com.quizlet.partskit.widgets.QButton;

/* loaded from: classes2.dex */
public final class a implements androidx.viewbinding.a {
    public final ScrollView a;
    public final QButton b;
    public final AssemblyInputEditText c;
    public final AssemblyInputEditText d;

    public a(ScrollView scrollView, QButton qButton, AssemblyInputEditText assemblyInputEditText, AssemblyInputEditText assemblyInputEditText2) {
        this.a = scrollView;
        this.b = qButton;
        this.c = assemblyInputEditText;
        this.d = assemblyInputEditText2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
