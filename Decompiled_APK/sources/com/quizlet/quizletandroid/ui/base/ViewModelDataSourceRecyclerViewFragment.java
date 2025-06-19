package com.quizlet.quizletandroid.ui.base;

import android.os.Bundle;
import android.view.View;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public abstract class ViewModelDataSourceRecyclerViewFragment<T> extends RecyclerViewFragment {
    public com.quizlet.quizletandroid.ui.base.viewmodel.a s;

    public abstract void W(List list);

    public abstract com.quizlet.quizletandroid.ui.base.viewmodel.a X();

    public void Y(com.quizlet.infra.legacysyncengine.net.request.c cVar) {
    }

    public abstract boolean a0();

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.s = X();
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        this.l.b(false);
        com.quizlet.quizletandroid.ui.base.viewmodel.a aVar = this.s;
        if (aVar == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        aVar.d.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(8, new com.quizlet.login.common.navigation.d(1, this, ViewModelDataSourceRecyclerViewFragment.class, "bindData", "bindData(Ljava/util/List;)V", 0, 18)));
        com.quizlet.quizletandroid.ui.base.viewmodel.a aVar2 = this.s;
        if (aVar2 == null) {
            Intrinsics.m("viewModel");
            throw null;
        }
        aVar2.e.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(8, new com.quizlet.login.common.navigation.d(1, this, ViewModelDataSourceRecyclerViewFragment.class, "setIsRefreshing", "setIsRefreshing(Z)V", 0, 19)));
        com.quizlet.quizletandroid.ui.base.viewmodel.a aVar3 = this.s;
        if (aVar3 != null) {
            aVar3.f.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(8, new J(this, 29)));
        } else {
            Intrinsics.m("viewModel");
            throw null;
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void r() {
        com.quizlet.quizletandroid.ui.base.viewmodel.a aVar = this.s;
        if (aVar != null) {
            aVar.B();
        } else {
            Intrinsics.m("viewModel");
            throw null;
        }
    }
}
