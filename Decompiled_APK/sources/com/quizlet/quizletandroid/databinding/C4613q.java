package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.widget.NestedScrollView;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;

/* renamed from: com.quizlet.quizletandroid.databinding.q, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4613q implements androidx.viewbinding.a {
    public final CoordinatorLayout a;
    public final View b;
    public final NestedScrollView c;
    public final StatefulIconFontTextView d;
    public final ImageView e;
    public final DiagramView f;
    public final QStarIconView g;
    public final QTextView h;
    public final QTextView i;
    public final QTextView j;
    public final ImageView k;
    public final QTextView l;
    public final FrameLayout m;
    public final com.quizlet.features.infra.legacyadapter.databinding.f n;

    public C4613q(CoordinatorLayout coordinatorLayout, View view, NestedScrollView nestedScrollView, StatefulIconFontTextView statefulIconFontTextView, ImageView imageView, DiagramView diagramView, QStarIconView qStarIconView, QTextView qTextView, QTextView qTextView2, QTextView qTextView3, ImageView imageView2, QTextView qTextView4, FrameLayout frameLayout, com.quizlet.features.infra.legacyadapter.databinding.f fVar) {
        this.a = coordinatorLayout;
        this.b = view;
        this.c = nestedScrollView;
        this.d = statefulIconFontTextView;
        this.e = imageView;
        this.f = diagramView;
        this.g = qStarIconView;
        this.h = qTextView;
        this.i = qTextView2;
        this.j = qTextView3;
        this.k = imageView2;
        this.l = qTextView4;
        this.m = frameLayout;
        this.n = fVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
