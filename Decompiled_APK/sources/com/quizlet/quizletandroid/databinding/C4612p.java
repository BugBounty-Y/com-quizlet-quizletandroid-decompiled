package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.RelativeLayout;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;

/* renamed from: com.quizlet.quizletandroid.databinding.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4612p implements androidx.viewbinding.a {
    public final RelativeLayout a;
    public final DiagramView b;

    public C4612p(RelativeLayout relativeLayout, DiagramView diagramView) {
        this.a = relativeLayout;
        this.b = diagramView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
