package com.quizlet.features.infra.legacyadapter.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.Toolbar;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.assembly.widgets.AssemblyBadge;
import com.quizlet.partskit.widgets.QTabLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.login.accountrecovery.signupduplicate.ExistingAccountView;
import com.quizlet.upgrade.ui.widgets.UpgradeTimelineSectionLayout;

/* loaded from: classes3.dex */
public final class h implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final View b;
    public final View c;
    public final View d;
    public final ViewGroup e;
    public final Object f;

    public /* synthetic */ h(ViewGroup viewGroup, View view, ViewGroup viewGroup2, ViewGroup viewGroup3, Object obj, int i) {
        this.a = i;
        this.e = viewGroup;
        this.b = view;
        this.d = viewGroup2;
        this.c = viewGroup3;
        this.f = obj;
    }

    public static h a(View view) {
        AppBarLayout appBarLayout = (AppBarLayout) view;
        int i = R.id.appbar_header;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.appbar_header, view);
        if (frameLayout != null) {
            i = R.id.tablayout;
            QTabLayout qTabLayout = (QTabLayout) AbstractC3375o2.c(R.id.tablayout, view);
            if (qTabLayout != null) {
                i = R.id.toolbar;
                Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, view);
                if (toolbar != null) {
                    return new h(appBarLayout, appBarLayout, frameLayout, qTabLayout, toolbar, 2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public static h b(View view) {
        int i = R.id.segmented_bucket_bottom_bar;
        View viewC = AbstractC3375o2.c(R.id.segmented_bucket_bottom_bar, view);
        if (viewC != null) {
            i = R.id.segmented_bucket_corner_image;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.segmented_bucket_corner_image, view);
            if (imageView != null) {
                i = R.id.segmented_bucket_count_text;
                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.segmented_bucket_count_text, view);
                if (qTextView != null) {
                    i = R.id.segmented_bucket_label_text;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.segmented_bucket_label_text, view);
                    if (qTextView2 != null) {
                        return new h(viewC, imageView, (CardView) view, qTextView, qTextView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public static h c(LayoutInflater layoutInflater, ExistingAccountView existingAccountView) {
        layoutInflater.inflate(R.layout.existing_account_view, existingAccountView);
        int i = R.id.badge;
        AssemblyBadge assemblyBadge = (AssemblyBadge) AbstractC3375o2.c(R.id.badge, existingAccountView);
        if (assemblyBadge != null) {
            i = R.id.email;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.email, existingAccountView);
            if (qTextView != null) {
                i = R.id.image;
                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.image, existingAccountView);
                if (imageView != null) {
                    i = R.id.username;
                    QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.username, existingAccountView);
                    if (qTextView2 != null) {
                        return new h(existingAccountView, assemblyBadge, qTextView, imageView, qTextView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(existingAccountView.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (ConstraintLayout) this.e;
            case 1:
                return this.e;
            case 2:
                return (AppBarLayout) this.e;
            case 3:
                return (CardView) this.e;
            case 4:
                return (ConstraintLayout) this.e;
            default:
                return (UpgradeTimelineSectionLayout) this.e;
        }
    }

    public /* synthetic */ h(ConstraintLayout constraintLayout, TextView textView, ImageView imageView, TextView textView2, View view, int i) {
        this.a = i;
        this.e = constraintLayout;
        this.b = textView;
        this.c = imageView;
        this.d = textView2;
        this.f = view;
    }

    public h(ViewGroup viewGroup, AssemblyBadge assemblyBadge, QTextView qTextView, ImageView imageView, QTextView qTextView2) {
        this.a = 1;
        this.e = viewGroup;
        this.f = assemblyBadge;
        this.b = qTextView;
        this.c = imageView;
        this.d = qTextView2;
    }

    public h(View view, ImageView imageView, CardView cardView, QTextView qTextView, QTextView qTextView2) {
        this.a = 3;
        this.e = cardView;
        this.f = view;
        this.c = imageView;
        this.b = qTextView;
        this.d = qTextView2;
    }
}
