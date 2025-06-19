package com.quizlet.baseui.base;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.J6;
import com.google.android.material.bottomsheet.i;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public abstract class BaseDaggerBottomSheetDialogFragment<T extends androidx.viewbinding.a> extends i implements dagger.android.c {
    public androidx.viewbinding.a q;
    public C4636c r;

    public abstract androidx.viewbinding.a Q(LayoutInflater layoutInflater, ViewGroup viewGroup);

    @Override // dagger.android.c
    public final C4636c c() {
        C4636c c4636c = this.r;
        if (c4636c != null) {
            return c4636c;
        }
        Intrinsics.m("androidInjector");
        throw null;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (!(this instanceof dagger.hilt.android.internal.migration.a)) {
            J6.c(this);
        }
        super.onAttach(context);
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        androidx.viewbinding.a aVarQ = Q(inflater, viewGroup);
        this.q = aVarQ;
        return aVarQ.getRoot();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        super.onDestroyView();
        this.q = null;
    }
}
