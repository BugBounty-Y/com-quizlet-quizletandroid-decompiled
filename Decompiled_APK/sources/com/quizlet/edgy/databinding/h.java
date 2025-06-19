package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class h implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final TextView b;
    public final TextView c;

    public h(ConstraintLayout constraintLayout, TextView textView, TextView textView2) {
        this.a = constraintLayout;
        this.b = textView;
        this.c = textView2;
    }

    public static h a(View view) {
        int i = R.id.search_school_city_and_state;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.search_school_city_and_state, view);
        if (textView != null) {
            i = R.id.search_school_name;
            TextView textView2 = (TextView) AbstractC3375o2.c(R.id.search_school_name, view);
            if (textView2 != null) {
                return new h((ConstraintLayout) view, textView, textView2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
