package com.quizlet.explanations.databinding;

import android.view.View;
import android.widget.ImageView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class q implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final ImageView b;
    public final QTextView c;
    public final AssemblyPill d;

    public q(ConstraintLayout constraintLayout, ImageView imageView, QTextView qTextView, AssemblyPill assemblyPill) {
        this.a = constraintLayout;
        this.b = imageView;
        this.c = qTextView;
        this.d = assemblyPill;
    }

    public static q a(View view) {
        int i = R.id.chapter_menu_item_chevron;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.chapter_menu_item_chevron, view);
        if (imageView != null) {
            i = R.id.chapter_menu_item_text;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.chapter_menu_item_text, view);
            if (qTextView != null) {
                i = R.id.coming_soon_badge;
                AssemblyPill assemblyPill = (AssemblyPill) AbstractC3375o2.c(R.id.coming_soon_badge, view);
                if (assemblyPill != null) {
                    return new q((ConstraintLayout) view, imageView, qTextView, assemblyPill);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
