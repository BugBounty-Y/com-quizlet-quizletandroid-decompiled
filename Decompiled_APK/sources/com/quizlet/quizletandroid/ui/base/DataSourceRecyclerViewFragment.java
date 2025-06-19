package com.quizlet.quizletandroid.ui.base;

import android.os.Bundle;
import android.view.View;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.infra.legacysyncengine.datasources.c;
import com.quizlet.infra.legacysyncengine.datasources.o;
import com.quizlet.quizletandroid.ui.profile.ProfileFragment;
import java.lang.ref.WeakReference;
import java.util.List;

@Deprecated
/* loaded from: classes3.dex */
public abstract class DataSourceRecyclerViewFragment<T, M extends com.quizlet.infra.legacysyncengine.datasources.c, A extends AbstractC1361d0> extends RecyclerViewFragment implements com.quizlet.infra.legacysyncengine.datasources.b {
    public WeakReference s;

    public abstract void W(List list);

    public abstract boolean X();

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List list) {
        if (isAdded()) {
            W(list);
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        this.s = null;
        super.onDetach();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPause() {
        super.onPause();
        com.quizlet.infra.legacysyncengine.datasources.c cVar = (com.quizlet.infra.legacysyncengine.datasources.c) this.s.get();
        if (cVar != null) {
            cVar.a(this);
            if (cVar instanceof o) {
                ((o) cVar).g();
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        com.quizlet.infra.legacysyncengine.datasources.c cVarV;
        super.onResume();
        Object context = getContext();
        androidx.savedstate.f parentFragment = getParentFragment();
        if (parentFragment != null && (parentFragment instanceof a)) {
            cVarV = ((ProfileFragment) ((a) parentFragment)).V(this);
        } else {
            if (!(context instanceof a)) {
                throw new RuntimeException("Context " + context + " must implement DataSourceProvider");
            }
            cVarV = ((ProfileFragment) ((a) context)).V(this);
        }
        WeakReference weakReference = this.s;
        com.quizlet.infra.legacysyncengine.datasources.c cVar = weakReference != null ? (com.quizlet.infra.legacysyncengine.datasources.c) weakReference.get() : null;
        if (this.s == null || cVar == null || !cVar.equals(cVarV)) {
            if (cVar != null) {
                cVar.a(this);
            }
            this.s = new WeakReference(cVarV);
            cVarV.e(this);
        }
        com.quizlet.infra.legacysyncengine.datasources.c cVar2 = (com.quizlet.infra.legacysyncengine.datasources.c) this.s.get();
        if (cVar2 != null) {
            cVar2.e(this);
            r();
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        super.onViewCreated(view, bundle);
        this.l.b(false);
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void r() {
        com.quizlet.infra.legacysyncengine.datasources.c cVar = (com.quizlet.infra.legacysyncengine.datasources.c) this.s.get();
        if (cVar != null) {
            this.l.c(true);
            G(cVar.d().s(io.reactivex.rxjava3.android.schedulers.b.a()).u(new com.quizlet.billing.subscriptions.a(this, 11), new com.quizlet.billing.subscriptions.c(3), io.reactivex.rxjava3.internal.functions.d.c));
        }
    }
}
