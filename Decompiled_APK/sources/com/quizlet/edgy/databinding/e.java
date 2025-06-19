package com.quizlet.edgy.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QEditText;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class e implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ConstraintLayout b;

    public /* synthetic */ e(ConstraintLayout constraintLayout, int i) {
        this.a = i;
        this.b = constraintLayout;
    }

    public static e a(View view) {
        if (((TextView) AbstractC3375o2.c(R.id.popularSchoolsText, view)) != null) {
            return new e((ConstraintLayout) view, 0);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.popularSchoolsText)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return this.b;
    }

    public e(ConstraintLayout constraintLayout, QEditText qEditText, ProgressBar progressBar, ImageView imageView) {
        this.a = 1;
        this.b = constraintLayout;
    }
}
