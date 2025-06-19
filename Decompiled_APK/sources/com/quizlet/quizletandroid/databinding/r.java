package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.RelativeLayout;
import com.quizlet.diagrams.layoutmanager.SnapRecyclerView;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;

/* loaded from: classes3.dex */
public final class r implements androidx.viewbinding.a {
    public final RelativeLayout a;
    public final DiagramView b;
    public final SnapRecyclerView c;

    public r(RelativeLayout relativeLayout, DiagramView diagramView, SnapRecyclerView snapRecyclerView) {
        this.a = relativeLayout;
        this.b = diagramView;
        this.c = snapRecyclerView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
