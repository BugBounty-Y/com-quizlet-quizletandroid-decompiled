package com.quizlet.quizletandroid.ui.setpage.terms;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.node.B;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.AbstractC1361d0;
import com.google.firebase.messaging.p;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.eventlogger.model.AudioPlaybackCountsLog;
import com.quizlet.features.setpage.r;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class TermListFragment extends Hilt_TermListFragment implements com.quizlet.features.setpage.termlist.contracts.a {
    public static final String H;
    public List A;
    public SetPagePerformanceLogger B;
    public WeakReference C;
    public com.quizlet.quizletandroid.ui.common.adapter.h D;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e E = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(P.class), new g(this, 0), new g(this, 2), new g(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e F;
    public final u G;
    public com.google.mlkit.vision.documentscanner.internal.c x;
    public com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c y;
    public androidx.work.impl.model.c z;

    static {
        Intrinsics.checkNotNullExpressionValue("TermListFragment", "getSimpleName(...)");
        H = "TermListFragment";
    }

    public TermListFragment() {
        a aVar = new a(this, 0);
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new g(this, 3), 22));
        this.F = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.setpage.terms.viewmodel.c.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 29), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 13), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(aVar, kVarA, 12));
        this.G = l.b(new a(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return H;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final AbstractC1361d0 Q() {
        com.quizlet.quizletandroid.ui.common.adapter.h hVar = new com.quizlet.quizletandroid.ui.common.adapter.h(requireContext(), new b(this));
        this.D = hVar;
        hVar.k = new b(this);
        hVar.l = new b(this);
        hVar.m = new com.quizlet.quizletandroid.ui.login.h(this, 3);
        com.quizlet.quizletandroid.ui.common.adapter.h hVar2 = this.D;
        if (hVar2 == null) {
            Intrinsics.m("termListAdapter");
            throw null;
        }
        com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c cVar = this.y;
        if (cVar != null) {
            return new com.quizlet.quizletandroid.ui.common.ads.nativeads.adapters.a(hVar2, cVar);
        }
        Intrinsics.m("adModule");
        throw null;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View R(ViewGroup parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_empty_term_list, parent, false);
        ViewGroup viewGroup = (ViewGroup) viewInflate.findViewById(R.id.empty_set_termlist_permission_error);
        Intrinsics.d(viewGroup);
        a0(viewGroup);
        return viewInflate;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final View S(ViewGroup parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewS = super.S(parent);
        ViewGroup viewGroup = (ViewGroup) viewS.findViewById(R.id.list_error_network_connection);
        Intrinsics.d(viewGroup);
        a0(viewGroup);
        return viewS;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final boolean T(int i) {
        return true;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void U(boolean z) {
        WeakReference weakReference = this.C;
        if (weakReference == null) {
            Intrinsics.m("loadingSpinnerDelegate");
            throw null;
        }
        com.quizlet.features.setpage.termlist.contracts.b bVar = (com.quizlet.features.setpage.termlist.contracts.b) weakReference.get();
        if (bVar != null) {
            ((r) bVar).U(z);
        } else {
            super.U(z);
        }
    }

    public final void a0(ViewGroup viewGroup) {
        ViewGroup.LayoutParams layoutParams = viewGroup.getLayoutParams();
        if (!(layoutParams instanceof ViewGroup.MarginLayoutParams)) {
            timber.log.c.a.e(new RuntimeException(B.d(layoutParams.getClass(), "Empty layout params must implement ViewGroup.MarginLayoutParams: ")));
        } else {
            ((ViewGroup.MarginLayoutParams) layoutParams).bottomMargin = kotlin.math.c.b(getResources().getDimension(R.dimen.empty_view_bottom_margin));
            viewGroup.setLayoutParams(layoutParams);
        }
    }

    public final P b0() {
        return (P) this.E.getValue();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        if (i == 100 && i2 == -1) {
            SortOption sortOption = SortOption.Companion.fromInt(intent != null ? intent.getIntExtra("selected_sort", SortOption.ORIGINAL.getValue()) : SortOption.ORIGINAL.getValue());
            com.quizlet.features.setpage.terms.viewmodel.c cVar = (com.quizlet.features.setpage.terms.viewmodel.c) this.F.getValue();
            cVar.getClass();
            Intrinsics.checkNotNullParameter(sortOption, "sortOption");
            com.quizlet.db.a aVar = cVar.f;
            aVar.getClass();
            aVar.a.edit().putInt(android.support.v4.media.session.a.g(cVar.i, "_sort_option", new StringBuilder("set_page_")), sortOption.getValue()).apply();
            cVar.j.e = sortOption;
            cVar.B(true);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.quizlet.quizletandroid.ui.setpage.terms.Hilt_TermListFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        this.C = context instanceof com.quizlet.features.setpage.termlist.contracts.b ? new WeakReference((com.quizlet.features.setpage.termlist.contracts.b) context) : new WeakReference(null);
        io.reactivex.rxjava3.internal.observers.e eVarI = b0().E().i(new c(this, 0), io.reactivex.rxjava3.internal.functions.d.e);
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        G(eVarI);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        super.onDetach();
        WeakReference weakReference = this.C;
        if (weakReference != null) {
            weakReference.clear();
        } else {
            Intrinsics.m("loadingSpinnerDelegate");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        P pB0 = b0();
        int iT0 = this.m.T0();
        p pVar = pB0.f;
        pVar.getClass();
        EventLoggerExt.c((EventLogger) pVar.b, new com.quizlet.features.setpage.logging.a(iT0, 0));
        com.quizlet.quizletandroid.ui.common.adapter.h hVar = this.D;
        if (hVar == null) {
            Intrinsics.m("termListAdapter");
            throw null;
        }
        hVar.j.dispose();
        EventLogger eventLogger = hVar.e;
        com.quizlet.quizletandroid.ui.common.adapter.presenter.e eVar = hVar.b;
        com.quizlet.quizletandroid.managers.audio.b bVar = eVar.e;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        HashSet hashSet = bVar.a;
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            eventLogger.v((AudioPlaybackCountsLog) it2.next());
        }
        hashSet.clear();
        eVar.c.b(true);
        io.reactivex.rxjava3.internal.observers.e eVar2 = eVar.h;
        if (eVar2 != null && !eVar2.b()) {
            io.reactivex.rxjava3.internal.disposables.a.a(eVar2);
        }
        eVar.f = null;
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment, com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        WeakReference weakReference = this.C;
        if (weakReference == null) {
            Intrinsics.m("loadingSpinnerDelegate");
            throw null;
        }
        if (weakReference.get() != null) {
            super.U(false);
        }
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new f(this, null), 3);
    }

    @Override // com.quizlet.features.infra.legacyadapter.RecyclerViewFragment
    public final void r() {
        ((com.quizlet.features.setpage.terms.viewmodel.c) this.F.getValue()).B(true);
    }
}
