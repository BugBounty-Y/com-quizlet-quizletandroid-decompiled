package com.quizlet.assembly.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.core.widget.NestedScrollView;
import com.quizlet.assembly.widgets.AssemblyCard;

/* loaded from: classes2.dex */
public final class b implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ViewGroup b;
    public final View c;

    public /* synthetic */ b(int i, View view, ViewGroup viewGroup) {
        this.a = i;
        this.b = viewGroup;
        this.c = view;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (AssemblyCard) this.b;
            case 1:
                return (LinearLayout) this.b;
            case 2:
                return (com.quizlet.quizletandroid.ui.setcreation.views.a) this.b;
            case 3:
                return (RelativeLayout) this.b;
            default:
                return (NestedScrollView) this.b;
        }
    }
}
