package com.quizlet.quizletandroid.ui.common.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewStub;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.StatefulTintImageView;
import com.quizlet.uicommon.ui.common.widgets.QFormField;

/* loaded from: classes3.dex */
public final class f implements androidx.viewbinding.a {
    public final ViewGroup a;
    public final StatefulTintImageView b;
    public final QTextView c;
    public final QTextView d;
    public final FrameLayout e;
    public final View f;
    public final ViewStub g;
    public final FrameLayout h;
    public final QTextView i;
    public final FrameLayout j;
    public final StatefulTintImageView k;
    public final ProgressBar l;
    public final QTextView m;
    public final FrameLayout n;
    public final TextView o;

    public f(ViewGroup viewGroup, StatefulTintImageView statefulTintImageView, QTextView qTextView, QTextView qTextView2, FrameLayout frameLayout, View view, ViewStub viewStub, FrameLayout frameLayout2, QTextView qTextView3, FrameLayout frameLayout3, StatefulTintImageView statefulTintImageView2, ProgressBar progressBar, QTextView qTextView4, FrameLayout frameLayout4, TextView textView) {
        this.a = viewGroup;
        this.b = statefulTintImageView;
        this.c = qTextView;
        this.d = qTextView2;
        this.e = frameLayout;
        this.f = view;
        this.g = viewStub;
        this.h = frameLayout2;
        this.i = qTextView3;
        this.j = frameLayout3;
        this.k = statefulTintImageView2;
        this.l = progressBar;
        this.m = qTextView4;
        this.n = frameLayout4;
        this.o = textView;
    }

    public static f a(LayoutInflater layoutInflater, QFormField qFormField) {
        layoutInflater.inflate(R.layout.widget_form_field, qFormField);
        int i = R.id.widget_form_field_action_icon;
        StatefulTintImageView statefulTintImageView = (StatefulTintImageView) AbstractC3375o2.c(R.id.widget_form_field_action_icon, qFormField);
        if (statefulTintImageView != null) {
            i = R.id.widget_form_field_action_icon_text;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.widget_form_field_action_icon_text, qFormField);
            if (qTextView != null) {
                i = R.id.widget_form_field_action_text;
                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.widget_form_field_action_text, qFormField);
                if (qTextView2 != null) {
                    i = R.id.widget_form_field_action_wrapper;
                    FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.widget_form_field_action_wrapper, qFormField);
                    if (frameLayout != null) {
                        i = R.id.widget_form_field_default_underline;
                        View viewC = AbstractC3375o2.c(R.id.widget_form_field_default_underline, qFormField);
                        if (viewC != null) {
                            i = R.id.widget_form_field_edittext_stub;
                            ViewStub viewStub = (ViewStub) AbstractC3375o2.c(R.id.widget_form_field_edittext_stub, qFormField);
                            if (viewStub != null) {
                                i = R.id.widget_form_field_icon_wrapper;
                                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.widget_form_field_icon_wrapper, qFormField);
                                if (frameLayout2 != null) {
                                    i = R.id.widget_form_field_label;
                                    QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.widget_form_field_label, qFormField);
                                    if (qTextView3 != null) {
                                        i = R.id.widget_form_field_label_wrapper;
                                        FrameLayout frameLayout3 = (FrameLayout) AbstractC3375o2.c(R.id.widget_form_field_label_wrapper, qFormField);
                                        if (frameLayout3 != null) {
                                            i = R.id.widget_form_field_status_icon;
                                            StatefulTintImageView statefulTintImageView2 = (StatefulTintImageView) AbstractC3375o2.c(R.id.widget_form_field_status_icon, qFormField);
                                            if (statefulTintImageView2 != null) {
                                                i = R.id.widget_form_field_status_progress;
                                                ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.widget_form_field_status_progress, qFormField);
                                                if (progressBar != null) {
                                                    i = R.id.widget_form_field_status_text;
                                                    QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.widget_form_field_status_text, qFormField);
                                                    if (qTextView4 != null) {
                                                        i = R.id.widget_form_field_status_wrapper;
                                                        FrameLayout frameLayout4 = (FrameLayout) AbstractC3375o2.c(R.id.widget_form_field_status_wrapper, qFormField);
                                                        if (frameLayout4 != null) {
                                                            i = R.id.widget_form_field_text_alignment_view;
                                                            TextView textView = (TextView) AbstractC3375o2.c(R.id.widget_form_field_text_alignment_view, qFormField);
                                                            if (textView != null) {
                                                                return new f(qFormField, statefulTintImageView, qTextView, qTextView2, frameLayout, viewC, viewStub, frameLayout2, qTextView3, frameLayout3, statefulTintImageView2, progressBar, qTextView4, frameLayout4, textView);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(qFormField.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
