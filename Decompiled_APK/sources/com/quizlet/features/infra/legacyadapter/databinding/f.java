package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public final class f implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final Object b;
    public final View c;
    public final View d;
    public final Object e;

    public /* synthetic */ f(ViewGroup viewGroup, View view, View view2, View view3, int i) {
        this.a = i;
        this.b = viewGroup;
        this.c = view;
        this.d = view2;
        this.e = view3;
    }

    public static f a(View view) {
        int i = R.id.view_empty_add_sets_button;
        QButton qButton = (QButton) AbstractC3375o2.c(R.id.view_empty_add_sets_button, view);
        if (qButton != null) {
            i = R.id.view_empty_header;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.view_empty_header, view);
            if (qTextView != null) {
                i = R.id.view_empty_message;
                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.view_empty_message, view);
                if (qTextView2 != null) {
                    return new f((CardView) view, qButton, qTextView, qTextView2, 6);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public static f b(View view) {
        int i = R.id.study_mode_settings_toolbar_title;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.study_mode_settings_toolbar_title, view);
        if (qTextView != null) {
            i = R.id.study_mode_settings_toolbar_up_button;
            FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.study_mode_settings_toolbar_up_button, view);
            if (frameLayout != null) {
                i = R.id.study_mode_settings_toolbar_up_icon;
                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.study_mode_settings_toolbar_up_icon, view);
                if (imageView != null) {
                    return new f((LinearLayout) view, qTextView, frameLayout, imageView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
        }
        return (ConstraintLayout) this.c;
    }

    public /* synthetic */ f(ConstraintLayout constraintLayout, Object obj, View view, Object obj2, int i) {
        this.a = i;
        this.c = constraintLayout;
        this.b = obj;
        this.d = view;
        this.e = obj2;
    }

    public f(LinearLayout linearLayout, QTextView qTextView, FrameLayout frameLayout, ImageView imageView) {
        this.a = 10;
        this.b = linearLayout;
        this.d = qTextView;
        this.c = frameLayout;
        this.e = imageView;
    }
}
