package com.quizlet.quizletandroid.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;

/* renamed from: com.quizlet.quizletandroid.databinding.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4602f implements androidx.viewbinding.a {
    public final FrameLayout a;
    public final com.quizlet.features.infra.legacyadapter.databinding.h b;
    public final RecyclerView c;

    public C4602f(FrameLayout frameLayout, com.quizlet.features.infra.legacyadapter.databinding.h hVar, RecyclerView recyclerView) {
        this.a = frameLayout;
        this.b = hVar;
        this.c = recyclerView;
    }

    public static C4602f a(LayoutInflater layoutInflater) {
        View viewInflate = layoutInflater.inflate(R.layout.activity_edit_set_language_selection, (ViewGroup) null, false);
        int i = R.id.appbar;
        View viewC = AbstractC3375o2.c(R.id.appbar, viewInflate);
        if (viewC != null) {
            com.quizlet.features.infra.legacyadapter.databinding.h hVarA = com.quizlet.features.infra.legacyadapter.databinding.h.a(viewC);
            RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.edit_set_language_list, viewInflate);
            if (recyclerView != null) {
                return new C4602f((FrameLayout) viewInflate, hVarA, recyclerView);
            }
            i = R.id.edit_set_language_list;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
