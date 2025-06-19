package com.quizlet.uicommon.ui.common.dialogs;

import android.app.Dialog;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public abstract class UnstyledConvertibleModalDialogFragment extends BaseViewBindingConvertibleModalDialogFragment<com.quizlet.quizletandroid.ui.common.databinding.d> {
    public boolean B;
    public final u C = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 10));
    public final com.google.android.material.bottomsheet.f D = new com.google.android.material.bottomsheet.f(this, 4);

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        return X() ? new com.google.android.material.bottomsheet.h(requireContext()) : new Dialog(requireContext(), ((Number) this.z.getValue()).intValue());
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.dialog_unstyled_convertable_modal, viewGroup, false);
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.contentFragment, viewInflate);
        if (frameLayout == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.contentFragment)));
        }
        com.quizlet.quizletandroid.ui.common.databinding.d dVar = new com.quizlet.quizletandroid.ui.common.databinding.d((ConstraintLayout) viewInflate, frameLayout);
        Intrinsics.checkNotNullExpressionValue(dVar, "inflate(...)");
        return dVar;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void V() {
        if (!X()) {
            if (a0() || b0()) {
                U(b0());
                return;
            }
            return;
        }
        T().setBackgroundResource(((Number) this.A.getValue()).intValue());
        BottomSheetBehavior bottomSheetBehaviorC = BottomSheetBehavior.C(T());
        bottomSheetBehaviorC.w(this.D);
        if (W()) {
            bottomSheetBehaviorC.J(3);
        }
        if (Y()) {
            T().getLayoutParams().height = -1;
            bottomSheetBehaviorC.I(Resources.getSystem().getDisplayMetrics().heightPixels);
            bottomSheetBehaviorC.J(3);
        }
    }

    public boolean W() {
        return this.B;
    }

    public final boolean X() {
        return ((Boolean) this.C.getValue()).booleanValue();
    }

    public boolean Y() {
        return false;
    }

    public boolean a0() {
        return false;
    }

    public boolean b0() {
        return false;
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onDestroyView() {
        if (X()) {
            BottomSheetBehavior.C(T()).g1.remove(this.D);
        }
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        ((com.quizlet.quizletandroid.ui.common.databinding.d) P()).b.removeAllViews();
        FrameLayout contentFragment = ((com.quizlet.quizletandroid.ui.common.databinding.d) P()).b;
        Intrinsics.checkNotNullExpressionValue(contentFragment, "contentFragment");
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        Intrinsics.checkNotNullExpressionValue(childFragmentManager, "getChildFragmentManager(...)");
        R(contentFragment, childFragmentManager);
    }
}
