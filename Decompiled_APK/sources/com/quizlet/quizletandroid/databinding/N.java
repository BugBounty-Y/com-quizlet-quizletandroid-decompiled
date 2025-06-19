package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class N implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final AssemblyPrimaryButton b;
    public final AssemblyTextButton c;
    public final FrameLayout d;
    public final ImageView e;
    public final QTextView f;
    public final QTextView g;

    public N(ConstraintLayout constraintLayout, AssemblyPrimaryButton assemblyPrimaryButton, AssemblyTextButton assemblyTextButton, FrameLayout frameLayout, ImageView imageView, QTextView qTextView, QTextView qTextView2) {
        this.a = constraintLayout;
        this.b = assemblyPrimaryButton;
        this.c = assemblyTextButton;
        this.d = frameLayout;
        this.e = imageView;
        this.f = qTextView;
        this.g = qTextView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
