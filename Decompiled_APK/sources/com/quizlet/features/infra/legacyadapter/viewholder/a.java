package com.quizlet.features.infra.legacyadapter.viewholder;

import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QEditText;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.I;
import com.quizlet.quizletandroid.databinding.K;
import com.quizlet.quizletandroid.databinding.m0;
import com.skydoves.balloon.internals.ViewPropertyKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ View b;

    public /* synthetic */ a(View view, int i) {
        this.a = i;
        this.b = view;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                View view = this.b;
                int i = R.id.empty_feed_text;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.empty_feed_text, view);
                if (qTextView != null) {
                    i = R.id.link_global_search;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.link_global_search, view);
                    if (qTextView2 != null) {
                        return new I((LinearLayout) view, qTextView, qTextView2);
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
            case 1:
                View view2 = this.b;
                int i2 = R.id.edit_filter_item;
                QEditText qEditText = (QEditText) AbstractC3375o2.c(R.id.edit_filter_item, view2);
                if (qEditText != null) {
                    i2 = R.id.filter_progress;
                    ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.filter_progress, view2);
                    if (progressBar != null) {
                        i2 = R.id.img_clear_filter;
                        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.img_clear_filter, view2);
                        if (imageView != null) {
                            com.quizlet.edgy.databinding.e eVar = new com.quizlet.edgy.databinding.e((ConstraintLayout) view2, qEditText, progressBar, imageView);
                            Intrinsics.checkNotNullExpressionValue(eVar, "bind(...)");
                            return eVar;
                        }
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(view2.getResources().getResourceName(i2)));
            case 2:
                View view3 = this.b;
                int i3 = R.id.leaderboard_profilepic;
                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.leaderboard_profilepic, view3);
                if (imageView2 != null) {
                    i3 = R.id.leaderboard_ranking;
                    QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.leaderboard_ranking, view3);
                    if (qTextView3 != null) {
                        i3 = R.id.leaderboard_time;
                        QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.leaderboard_time, view3);
                        if (qTextView4 != null) {
                            i3 = R.id.leaderboard_username;
                            QTextView qTextView5 = (QTextView) AbstractC3375o2.c(R.id.leaderboard_username, view3);
                            if (qTextView5 != null) {
                                return new K((CardView) view3, imageView2, qTextView3, qTextView4, qTextView5);
                            }
                        }
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(view3.getResources().getResourceName(i3)));
            case 3:
                View view4 = this.b;
                int i4 = R.id.edit_set_language_gap;
                View viewC = AbstractC3375o2.c(R.id.edit_set_language_gap, view4);
                if (viewC != null) {
                    i4 = R.id.edit_set_language_header;
                    QTextView qTextView6 = (QTextView) AbstractC3375o2.c(R.id.edit_set_language_header, view4);
                    if (qTextView6 != null) {
                        return new m0((LinearLayout) view4, viewC, qTextView6);
                    }
                }
                throw new NullPointerException("Missing required view with ID: ".concat(view4.getResources().getResourceName(i4)));
            default:
                return ViewPropertyKt.viewProperty$lambda$0(this.b);
        }
    }
}
