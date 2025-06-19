package com.onetrust.otpublishers.headless.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.appcompat.widget.Toolbar;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import com.quizlet.uicommon.ui.common.views.QuizletPlusLogo;

/* loaded from: classes2.dex */
public final class b implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final ViewGroup b;
    public final View c;
    public final Object d;

    public /* synthetic */ b(ViewGroup viewGroup, View view, View view2, int i) {
        this.a = i;
        this.b = viewGroup;
        this.c = view;
        this.d = view2;
    }

    public static b a(View view) {
        int i = R.id.appbar_header;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.appbar_header, view);
        if (frameLayout != null) {
            i = R.id.toolbar;
            Toolbar toolbar = (Toolbar) AbstractC3375o2.c(R.id.toolbar, view);
            if (toolbar != null) {
                return new b((AppBarLayout) view, frameLayout, toolbar, 2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    public static b b(View view) {
        int i = R.id.edit_set_language_check;
        IconFontTextView iconFontTextView = (IconFontTextView) AbstractC3375o2.c(R.id.edit_set_language_check, view);
        if (iconFontTextView != null) {
            i = R.id.edit_set_language_name;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.edit_set_language_name, view);
            if (qTextView != null) {
                return new b((ConstraintLayout) view, iconFontTextView, qTextView, 4);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i)));
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (CoordinatorLayout) this.b;
            case 1:
                return (DiagramView) this.b;
            case 2:
                return (AppBarLayout) this.b;
            case 3:
                return (CardView) this.b;
            case 4:
                return (ConstraintLayout) this.b;
            case 5:
                return (ConstraintLayout) this.b;
            case 6:
                return (LinearLayout) this.b;
            default:
                return (QuizletPlusLogo) this.b;
        }
    }

    public b(CoordinatorLayout coordinatorLayout, f fVar, CoordinatorLayout coordinatorLayout2) {
        this.a = 0;
        this.b = coordinatorLayout;
        this.d = fVar;
        this.c = coordinatorLayout2;
    }
}
