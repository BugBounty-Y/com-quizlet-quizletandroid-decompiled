package com.quizlet.assembly.databinding;

import android.view.View;
import android.widget.ImageView;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes2.dex */
public final class a implements androidx.viewbinding.a {
    public final AssemblyPill a;
    public final ImageView b;
    public final QTextView c;
    public final ImageView d;

    public a(AssemblyPill assemblyPill, ImageView imageView, QTextView qTextView, ImageView imageView2) {
        this.a = assemblyPill;
        this.b = imageView;
        this.c = qTextView;
        this.d = imageView2;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
