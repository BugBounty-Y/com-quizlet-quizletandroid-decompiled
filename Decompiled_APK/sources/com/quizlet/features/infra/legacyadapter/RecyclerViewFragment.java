package com.quizlet.features.infra.legacyadapter;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.emoji2.text.n;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.W;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.material.internal.q;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.group.classuser.ClassUserListFragment;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class RecyclerViewFragment extends BaseFragment<com.quizlet.features.infra.legacyadapter.databinding.a> implements com.quizlet.baserecyclerview.decoration.b {
    public LinearLayout e;
    public RecyclerView f;
    public FrameLayout g;
    public FrameLayout h;
    public ProgressBar i;
    public SwipeRefreshLayout j;
    public FrameLayout k;
    public q l;
    public LinearLayoutManager m;
    public AbstractC1361d0 n;
    public View p;
    public View q;
    public final W o = new W(this, 1);
    public final g r = new g(this);

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater layoutInflater, ViewGroup viewGroup) {
        View viewInflate = layoutInflater.inflate(R.layout.fragment_recyclerview, viewGroup, false);
        FrameLayout frameLayout = (FrameLayout) viewInflate;
        int i = R.id.fragment_recyclerview_content_container;
        LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.fragment_recyclerview_content_container, viewInflate);
        if (linearLayout != null) {
            i = R.id.fragment_recyclerview_empty_container;
            FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.fragment_recyclerview_empty_container, viewInflate);
            if (frameLayout2 != null) {
                i = R.id.fragment_recyclerview_promo_container;
                FrameLayout frameLayout3 = (FrameLayout) AbstractC3375o2.c(R.id.fragment_recyclerview_promo_container, viewInflate);
                if (frameLayout3 != null) {
                    i = R.id.fragment_recyclerview_recyclerview;
                    RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.fragment_recyclerview_recyclerview, viewInflate);
                    if (recyclerView != null) {
                        i = R.id.fragment_recyclerview_resize_container;
                        FrameLayout frameLayout4 = (FrameLayout) AbstractC3375o2.c(R.id.fragment_recyclerview_resize_container, viewInflate);
                        if (frameLayout4 != null) {
                            i = R.id.fragment_recyclerview_spinner;
                            ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.fragment_recyclerview_spinner, viewInflate);
                            if (progressBar != null) {
                                i = R.id.fragment_recyclerview_swipe_container;
                                SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) AbstractC3375o2.c(R.id.fragment_recyclerview_swipe_container, viewInflate);
                                if (swipeRefreshLayout != null) {
                                    return new com.quizlet.features.infra.legacyadapter.databinding.a(frameLayout, frameLayout, linearLayout, frameLayout2, frameLayout3, recyclerView, frameLayout4, progressBar, swipeRefreshLayout);
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public abstract AbstractC1361d0 Q();

    public abstract View R(ViewGroup viewGroup);

    public View S(ViewGroup viewGroup) {
        return Z.c(viewGroup, R.layout.view_empty_list_network_error, viewGroup, false);
    }

    public abstract boolean T(int i);

    public void U(boolean z) {
        this.i.setVisibility(z ? 0 : 8);
    }

    public boolean V() {
        return this instanceof ClassUserListFragment;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.n = Q();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        View viewOnCreateView = super.onCreateView(layoutInflater, viewGroup, bundle);
        this.e = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).c;
        this.f = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).f;
        this.g = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).g;
        this.h = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).d;
        this.i = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).h;
        this.j = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).i;
        this.k = ((com.quizlet.features.infra.legacyadapter.databinding.a) J()).e;
        return viewOnCreateView;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroy() {
        super.onDestroy();
        this.n = null;
    }

    /* JADX WARN: Type inference failed for: r3v1, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.f.setAdapter(null);
        super.onDestroyView();
        this.n.unregisterAdapterDataObserver(this.o);
        AbstractC1361d0 abstractC1361d0 = this.n;
        if (abstractC1361d0 instanceof e) {
            e eVar = (e) abstractC1361d0;
            eVar.g.dispose();
            n nVar = io.reactivex.rxjava3.internal.functions.d.b;
            eVar.g = new io.reactivex.rxjava3.disposables.d(nVar, 0);
            eVar.h.dispose();
            eVar.h = new io.reactivex.rxjava3.disposables.d(nVar, 0);
        }
        ((WeakReference) this.l.d).clear();
        this.m = null;
        this.e = null;
        this.f = null;
        this.g = null;
        this.h = null;
        this.i = null;
        this.j = null;
        this.k = null;
    }

    @Override // androidx.fragment.app.Fragment
    public void onSaveInstanceState(Bundle bundle) {
        RecyclerView recyclerView = this.f;
        if (recyclerView == null || recyclerView.getLayoutManager() == null) {
            return;
        }
        bundle.putParcelable("LayoutManagerState", this.f.getLayoutManager().k0());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        super.onViewCreated(view, bundle);
        g delegate = this.r;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        q qVar = new q();
        qVar.d = new WeakReference(delegate);
        this.l = qVar;
        this.j.setProgressBackgroundColorSchemeColor(com.quizlet.themes.extensions.a.a(getContext(), R.attr.SysColorCard));
        if (V()) {
            view.getViewTreeObserver().addOnGlobalLayoutListener(new h(this, view));
        }
        this.n.registerAdapterDataObserver(this.o);
        this.l.b(this.n.getItemCount() > 0);
        RecyclerView recyclerView = this.f;
        Context context = getContext();
        com.quizlet.baserecyclerview.decoration.d dVar = com.quizlet.baserecyclerview.decoration.d.a;
        recyclerView.i(new com.quizlet.baserecyclerview.decoration.e(context, R.dimen.listitem_vertical_margin));
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(getContext());
        this.m = linearLayoutManager;
        linearLayoutManager.k1(1);
        if (bundle != null && bundle.containsKey("LayoutManagerState")) {
            this.m.j0(bundle.getParcelable("LayoutManagerState"));
        }
        if (this.n.getItemCount() != 0) {
            this.f.setAdapter(this.n);
            this.f.setLayoutManager(this.m);
        }
        this.f.setItemAnimator(null);
        this.j.setColorSchemeColors(com.quizlet.themes.extensions.a.a(getContext(), R.attr.colorAccent));
        this.j.setOnRefreshListener(new com.google.android.material.search.a(this, 21));
    }

    public abstract void r();

    @Override // com.quizlet.baserecyclerview.decoration.b
    public final boolean z(int i) {
        if (!T(i)) {
            return false;
        }
        int i2 = i + 1;
        if (i2 >= this.n.getItemCount()) {
            return true;
        }
        return T(i2);
    }
}
