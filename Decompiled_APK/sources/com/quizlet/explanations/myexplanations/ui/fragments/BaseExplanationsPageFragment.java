package com.quizlet.explanations.myexplanations.ui.fragments;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.explanations.databinding.i;
import com.quizlet.explanations.myexplanations.viewmodel.m;
import com.quizlet.partskit.widgets.QProgressBar;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseExplanationsPageFragment extends BaseFragment<i> {
    public final e e = new e(K.a(m.class), new c(this, 0), new c(this, 2), new c(this, 1));

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_my_explanations_page, viewGroup, false);
        int i = R.id.emptyText;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.emptyText, viewInflate);
        if (qTextView != null) {
            i = R.id.progressBar;
            QProgressBar qProgressBar = (QProgressBar) AbstractC3375o2.c(R.id.progressBar, viewInflate);
            if (qProgressBar != null) {
                i = R.id.recyclerView;
                RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recyclerView, viewInflate);
                if (recyclerView != null) {
                    i iVar = new i((ConstraintLayout) viewInflate, qTextView, qProgressBar, recyclerView);
                    Intrinsics.checkNotNullExpressionValue(iVar, "inflate(...)");
                    return iVar;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final QTextView Q() {
        QTextView emptyText = ((i) J()).b;
        Intrinsics.checkNotNullExpressionValue(emptyText, "emptyText");
        return emptyText;
    }

    public final RecyclerView R() {
        RecyclerView recyclerView = ((i) J()).d;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "recyclerView");
        return recyclerView;
    }

    public final com.quizlet.explanations.myexplanations.viewmodel.a S() {
        return (com.quizlet.explanations.myexplanations.viewmodel.a) this.e.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        R().setAdapter(null);
        super.onDestroyView();
    }
}
