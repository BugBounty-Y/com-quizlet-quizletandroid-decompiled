package com.quizlet.explanations.feedback.ui.fragments;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment;

/* loaded from: classes2.dex */
public abstract class Hilt_ExplanationsFeedbackModalFragment extends UnstyledConvertibleModalDialogFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public dagger.hilt.android.internal.managers.j E;
    public boolean F;
    public volatile dagger.hilt.android.internal.managers.f G;
    public final Object H = new Object();
    public boolean I = false;

    public static boolean e0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void c0() {
        if (this.E == null) {
            this.E = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
            if (e0(getHost())) {
                this.F = M6.e(super.getContext());
            } else {
                this.F = true;
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.G == null) {
            synchronized (this.H) {
                try {
                    if (this.G == null) {
                        this.G = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.G.d();
    }

    public final void d0() {
        if (e0(getHost()) && !this.I) {
            this.I = true;
            ((ExplanationsFeedbackModalFragment) this).q = ((com.quizlet.quizletandroid.j) ((e) d())).d.a();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.F) {
            return null;
        }
        c0();
        return this.E;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !e0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        c0();
        d0();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.I;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.E;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        c0();
        d0();
    }
}
