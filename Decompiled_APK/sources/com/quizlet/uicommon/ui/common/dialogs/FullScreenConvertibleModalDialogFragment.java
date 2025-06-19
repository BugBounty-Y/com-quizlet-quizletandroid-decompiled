package com.quizlet.uicommon.ui.common.dialogs;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.behaviors.LockableBottomSheetBehavior;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public abstract class FullScreenConvertibleModalDialogFragment extends BaseViewBindingConvertibleModalDialogFragment<com.quizlet.quizletandroid.ui.common.databinding.a> {
    public final boolean B = true;
    public final com.google.android.material.bottomsheet.f C = new com.google.android.material.bottomsheet.f(this, 3);

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public Dialog K(Bundle bundle) {
        return ((Boolean) this.x.getValue()).booleanValue() ? new Dialog(requireContext(), ((Number) this.z.getValue()).intValue()) : new com.google.android.material.bottomsheet.h(requireContext());
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_full_screen_convertible_modal, viewGroup, false);
        int i = R.id.back;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.back, viewInflate);
        if (frameLayout != null) {
            i = R.id.backIcon;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.backIcon, viewInflate);
            if (imageView != null) {
                i = R.id.contentFragment;
                FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.contentFragment, viewInflate);
                if (frameLayout2 != null) {
                    i = R.id.modalTitleText;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.modalTitleText, viewInflate);
                    if (qTextView != null) {
                        com.quizlet.quizletandroid.ui.common.databinding.a aVar = new com.quizlet.quizletandroid.ui.common.databinding.a((CoordinatorLayout) viewInflate, frameLayout, imageView, frameLayout2, qTextView);
                        Intrinsics.checkNotNullExpressionValue(aVar, "inflate(...)");
                        return aVar;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void V() {
        if (((Boolean) this.x.getValue()).booleanValue()) {
            U(true);
            return;
        }
        View viewT = T();
        viewT.setBackgroundResource(((Number) this.A.getValue()).intValue());
        viewT.getLayoutParams().height = -1;
        LockableBottomSheetBehavior lockableBottomSheetBehavior = new LockableBottomSheetBehavior();
        lockableBottomSheetBehavior.p1 = X();
        lockableBottomSheetBehavior.w(this.C);
        ViewGroup.LayoutParams layoutParams = T().getLayoutParams();
        Intrinsics.e(layoutParams, "null cannot be cast to non-null type androidx.coordinatorlayout.widget.CoordinatorLayout.LayoutParams");
        ((androidx.coordinatorlayout.widget.e) layoutParams).b(lockableBottomSheetBehavior);
        lockableBottomSheetBehavior.J(this.B ? 3 : 6);
    }

    public String W() {
        return null;
    }

    public boolean X() {
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.quizletandroid.ui.common.databinding.a) P()).d.removeAllViews();
        FrameLayout contentFragment = ((com.quizlet.quizletandroid.ui.common.databinding.a) P()).d;
        Intrinsics.checkNotNullExpressionValue(contentFragment, "contentFragment");
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        R(contentFragment, childFragmentManager);
        ((com.quizlet.quizletandroid.ui.common.databinding.a) P()).b.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 27));
        com.onetrust.otpublishers.headless.UI.TVUI.fragments.f fVar = new com.onetrust.otpublishers.headless.UI.TVUI.fragments.f(this, 13);
        Dialog dialog = this.l;
        if (dialog != null) {
            dialog.setOnKeyListener(fVar);
        }
        String strW = W();
        QTextView qTextView = ((com.quizlet.quizletandroid.ui.common.databinding.a) P()).e;
        qTextView.setText(strW);
        qTextView.setVisibility(strW == null ? 8 : 0);
        getChildFragmentManager().o.add(new com.quizlet.explanations.textbook.ui.c(this, 1));
    }
}
