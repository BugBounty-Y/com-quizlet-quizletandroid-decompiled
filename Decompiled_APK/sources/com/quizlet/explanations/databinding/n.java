package com.quizlet.explanations.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.legacy.widget.Space;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblySecondaryButton;
import com.quizlet.features.setpage.progress.presentation.ui.SetPageProgressItemView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.views.ArcProgressLayout;
import com.quizlet.quizletandroid.ui.common.views.ContentTextView;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import com.quizlet.richtext.ui.MatchAutoResizeTextView;
import com.quizlet.uicommon.ui.common.views.ArcProgressBar;

/* loaded from: classes2.dex */
public final class n implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final View b;
    public final ViewGroup c;
    public final View d;
    public final View e;
    public final View f;
    public final View g;

    public /* synthetic */ n(ViewGroup viewGroup, QTextView qTextView, ImageView imageView, QTextView qTextView2, TextView textView, TextView textView2, int i) {
        this.a = i;
        this.c = viewGroup;
        this.d = qTextView;
        this.b = imageView;
        this.e = qTextView2;
        this.f = textView;
        this.g = textView2;
    }

    public static n a(LayoutInflater layoutInflater, ViewGroup viewGroup) {
        View viewInflate = layoutInflater.inflate(R.layout.set_term_item_view, viewGroup, false);
        int i = R.id.listitem_term_definition;
        ContentTextView contentTextView = (ContentTextView) AbstractC3375o2.c(R.id.listitem_term_definition, viewInflate);
        if (contentTextView != null) {
            i = R.id.listitem_term_definition_image;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.listitem_term_definition_image, viewInflate);
            if (imageView != null) {
                i = R.id.listitem_term_word;
                ContentTextView contentTextView2 = (ContentTextView) AbstractC3375o2.c(R.id.listitem_term_word, viewInflate);
                if (contentTextView2 != null) {
                    i = R.id.setpage_diagram_audio;
                    StatefulIconFontTextView statefulIconFontTextView = (StatefulIconFontTextView) AbstractC3375o2.c(R.id.setpage_diagram_audio, viewInflate);
                    if (statefulIconFontTextView != null) {
                        i = R.id.setpage_diagram_star;
                        QStarIconView qStarIconView = (QStarIconView) AbstractC3375o2.c(R.id.setpage_diagram_star, viewInflate);
                        if (qStarIconView != null) {
                            return new n((CardView) viewInflate, contentTextView, imageView, contentTextView2, statefulIconFontTextView, qStarIconView, 4);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (ConstraintLayout) this.c;
            case 1:
                return (SetPageProgressItemView) this.f;
            case 2:
                return (LinearLayout) this.c;
            case 3:
                return (MatchCardView) this.c;
            case 4:
                return (CardView) this.c;
            case 5:
                return (LinearLayout) this.c;
            default:
                return (ConstraintLayout) this.c;
        }
    }

    public n(SetPageProgressItemView setPageProgressItemView, ImageView imageView, ArcProgressBar arcProgressBar, ConstraintLayout constraintLayout, QTextView qTextView, QTextView qTextView2) {
        this.a = 1;
        this.f = setPageProgressItemView;
        this.b = imageView;
        this.g = arcProgressBar;
        this.c = constraintLayout;
        this.d = qTextView;
        this.e = qTextView2;
    }

    public n(MatchCardView matchCardView, RelativeLayout relativeLayout, View view, View view2, ImageView imageView, MatchAutoResizeTextView matchAutoResizeTextView) {
        this.a = 3;
        this.c = matchCardView;
        this.d = relativeLayout;
        this.e = view;
        this.f = view2;
        this.b = imageView;
        this.g = matchAutoResizeTextView;
    }

    public n(LinearLayout linearLayout, QButton qButton, LinearLayout linearLayout2, QTextView qTextView, QTextView qTextView2, QTextView qTextView3) {
        this.a = 2;
        this.c = linearLayout;
        this.g = qButton;
        this.b = linearLayout2;
        this.d = qTextView;
        this.e = qTextView2;
        this.f = qTextView3;
    }

    public n(LinearLayout linearLayout, Space space, ArcProgressLayout arcProgressLayout, QTextView qTextView, QButton qButton, QButton qButton2) {
        this.a = 5;
        this.c = linearLayout;
        this.e = space;
        this.f = arcProgressLayout;
        this.d = qTextView;
        this.g = qButton;
        this.b = qButton2;
    }

    public n(ConstraintLayout constraintLayout, AssemblyPrimaryButton assemblyPrimaryButton, AssemblySecondaryButton assemblySecondaryButton, QTextView qTextView, QTextView qTextView2, View view) {
        this.a = 6;
        this.c = constraintLayout;
        this.f = assemblyPrimaryButton;
        this.g = assemblySecondaryButton;
        this.d = qTextView;
        this.e = qTextView2;
        this.b = view;
    }
}
