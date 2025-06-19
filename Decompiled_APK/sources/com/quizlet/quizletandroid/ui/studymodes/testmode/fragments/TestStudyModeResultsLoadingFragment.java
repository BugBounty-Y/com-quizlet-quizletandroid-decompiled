package com.quizlet.quizletandroid.ui.studymodes.testmode.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.edgy.databinding.e;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class TestStudyModeResultsLoadingFragment extends BaseFragment<e> {
    public static final String f;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e e = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new d(this, 0), new d(this, 2), new d(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("TestStudyModeResultsLoadingFragment", "getSimpleName(...)");
        f = "TestStudyModeResultsLoadingFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return f;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_test_mode_results_loading, viewGroup, false);
        int i = R.id.messageTextView;
        if (((QTextView) AbstractC3375o2.c(R.id.messageTextView, viewInflate)) != null) {
            i = R.id.progressView;
            if (((ProgressBar) AbstractC3375o2.c(R.id.progressView, viewInflate)) != null) {
                e eVar = new e((ConstraintLayout) viewInflate, 2);
                Intrinsics.checkNotNullExpressionValue(eVar, "inflate(...)");
                return eVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        G g = (G) this.e.getValue();
        g.getClass();
        Intrinsics.checkNotNullParameter("loading", "screen");
        g.D.l("loading");
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        G g = (G) this.e.getValue();
        g.getClass();
        Intrinsics.checkNotNullParameter("loading", "screen");
        f.k(g.D, "loading", null, 6);
    }
}
