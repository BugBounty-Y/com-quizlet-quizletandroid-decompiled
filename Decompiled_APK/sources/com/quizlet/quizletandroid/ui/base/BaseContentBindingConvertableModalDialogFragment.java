package com.quizlet.quizletandroid.ui.base;

import android.view.LayoutInflater;
import android.view.View;
import android.widget.FrameLayout;
import androidx.viewbinding.a;
import com.quizlet.quizletandroid.ui.common.dialogs.BaseConvertableModalDialogFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public abstract class BaseContentBindingConvertableModalDialogFragment<T extends androidx.viewbinding.a> extends BaseConvertableModalDialogFragment {
    public androidx.viewbinding.a y;

    @Override // com.quizlet.quizletandroid.ui.common.dialogs.BaseConvertableModalDialogFragment
    public final View R(LayoutInflater inflater, FrameLayout contentFragmentFromBottomSheet) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Intrinsics.checkNotNullParameter(contentFragmentFromBottomSheet, "contentFragmentFromBottomSheet");
        androidx.viewbinding.a aVarS = S(inflater, contentFragmentFromBottomSheet);
        this.y = aVarS;
        View root = aVarS.getRoot();
        Intrinsics.checkNotNullExpressionValue(root, "getRoot(...)");
        return root;
    }

    public abstract androidx.viewbinding.a S(LayoutInflater layoutInflater, FrameLayout frameLayout);

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.y = null;
    }
}
