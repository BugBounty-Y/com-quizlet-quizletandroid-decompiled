package com.quizlet.baseui.base;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.viewbinding.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseViewBindingDialogFragment<T extends androidx.viewbinding.a> extends BaseDaggerDialogFragment {
    public androidx.viewbinding.a v;

    public final androidx.viewbinding.a P() {
        androidx.viewbinding.a aVar = this.v;
        if (aVar != null) {
            return aVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    public abstract androidx.viewbinding.a Q(LayoutInflater layoutInflater, ViewGroup viewGroup);

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        this.v = Q(inflater, viewGroup);
        return P().getRoot();
    }

    @Override // com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        this.v = null;
    }
}
