package com.quizlet.uicommon.ui.common.overflowmenu;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class FullscreenOverflowFragment extends DialogInterfaceOnCancelListenerC1151t implements com.quizlet.baserecyclerview.decoration.b {
    public com.quizlet.features.infra.legacyadapter.databinding.f q;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(i.class), new d(this, 0), new d(this, 2), new d(this, 1));
    public a s;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final void G() {
        s0 s0Var;
        Object value;
        H(false, false);
        i iVar = (i) this.r.getValue();
        do {
            s0Var = iVar.b;
            value = s0Var.getValue();
        } while (!s0Var.k(value, kotlin.collections.K.a));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.s = new a(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 11));
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_fullscreen_overflow, (ViewGroup) null, false);
        int i = R.id.cancelSeparator;
        View viewC = AbstractC3375o2.c(R.id.cancelSeparator, viewInflate);
        if (viewC != null) {
            i = R.id.itemCancel;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.itemCancel, viewInflate);
            if (qTextView != null) {
                i = R.id.menuRecyclerView;
                RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.menuRecyclerView, viewInflate);
                if (recyclerView != null) {
                    ConstraintLayout constraintLayout = (ConstraintLayout) viewInflate;
                    this.q = new com.quizlet.features.infra.legacyadapter.databinding.f(constraintLayout, (Object) viewC, (View) qTextView, (Object) recyclerView, 12);
                    Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
                    return constraintLayout;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        com.quizlet.features.infra.legacyadapter.databinding.f fVar = this.q;
        if (fVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        RecyclerView menuRecyclerView = (RecyclerView) fVar.e;
        Intrinsics.checkNotNullExpressionValue(menuRecyclerView, "menuRecyclerView");
        menuRecyclerView.setAdapter(null);
        this.q = null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onStart() {
        Window window;
        super.onStart();
        Dialog dialog = this.l;
        if (dialog == null || (window = dialog.getWindow()) == null) {
            return;
        }
        window.setLayout(-1, -1);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.features.infra.legacyadapter.databinding.f fVar = this.q;
        if (fVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        RecyclerView menuRecyclerView = (RecyclerView) fVar.e;
        Intrinsics.checkNotNullExpressionValue(menuRecyclerView, "menuRecyclerView");
        getContext();
        menuRecyclerView.setLayoutManager(new LinearLayoutManager(1));
        com.quizlet.baserecyclerview.decoration.c cVar = new com.quizlet.baserecyclerview.decoration.c(getContext(), 1, 0, this);
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        cVar.a.setColor(com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.colorPrimaryDark));
        menuRecyclerView.i(cVar);
        a aVar = this.s;
        if (aVar == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        menuRecyclerView.setAdapter(aVar);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new c(this, null), 3);
        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = this.q;
        if (fVar2 == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        QTextView itemCancel = (QTextView) fVar2.d;
        Intrinsics.checkNotNullExpressionValue(itemCancel, "itemCancel");
        itemCancel.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 29));
    }

    @Override // com.quizlet.baserecyclerview.decoration.b
    public final boolean z(int i) {
        a aVar = this.s;
        if (aVar != null) {
            return i != aVar.getItemCount() - 1;
        }
        Intrinsics.m("adapter");
        throw null;
    }
}
