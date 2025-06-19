package com.quizlet.quizletandroid.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class l0 implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final FrameLayout b;
    public final com.quizlet.features.infra.legacyadapter.databinding.f c;

    public l0(LinearLayout linearLayout, FrameLayout frameLayout, com.quizlet.features.infra.legacyadapter.databinding.f fVar) {
        this.a = linearLayout;
        this.b = frameLayout;
        this.c = fVar;
    }

    public static l0 a(LayoutInflater layoutInflater) {
        View viewInflate = layoutInflater.inflate(R.layout.study_mode_settings_activity, (ViewGroup) null, false);
        int i = R.id.fragment_container;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.fragment_container, viewInflate);
        if (frameLayout != null) {
            i = R.id.toolbarContainer;
            View viewC = AbstractC3375o2.c(R.id.toolbarContainer, viewInflate);
            if (viewC != null) {
                return new l0((LinearLayout) viewInflate, frameLayout, com.quizlet.features.infra.legacyadapter.databinding.f.b(viewC));
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
