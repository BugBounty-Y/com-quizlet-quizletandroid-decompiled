package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.cardview.widget.CardView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.VerticalFadingEdgeRecyclerView;

/* loaded from: classes3.dex */
public final class h0 implements androidx.viewbinding.a {
    public final View a;
    public final VerticalFadingEdgeRecyclerView b;
    public final AssemblyPill c;
    public final QTextView d;

    public h0(View view, VerticalFadingEdgeRecyclerView verticalFadingEdgeRecyclerView, AssemblyPill assemblyPill, QTextView qTextView) {
        this.a = view;
        this.b = verticalFadingEdgeRecyclerView;
        this.c = assemblyPill;
        this.d = qTextView;
    }

    public static h0 a(View view) {
        int i = R.id.card;
        if (((CardView) AbstractC3375o2.c(R.id.card, view)) != null) {
            i = R.id.search_set_preview_term_recycler_view;
            VerticalFadingEdgeRecyclerView verticalFadingEdgeRecyclerView = (VerticalFadingEdgeRecyclerView) AbstractC3375o2.c(R.id.search_set_preview_term_recycler_view, view);
            if (verticalFadingEdgeRecyclerView != null) {
                i = R.id.term_count;
                AssemblyPill assemblyPill = (AssemblyPill) AbstractC3375o2.c(R.id.term_count, view);
                if (assemblyPill != null) {
                    i = R.id.title;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.title, view);
                    if (qTextView != null) {
                        return new h0(view, verticalFadingEdgeRecyclerView, assemblyPill, qTextView);
                    }
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
