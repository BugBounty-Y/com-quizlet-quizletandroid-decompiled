package com.quizlet.login.recovery.forgotpassword.ui;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.baseui.base.BaseDaggerDialogFragment;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_ForgotPasswordDialogFragment extends BaseDaggerDialogFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j v;
    public boolean w;
    public volatile dagger.hilt.android.internal.managers.f x;
    public final Object y = new Object();
    public boolean z = false;

    public static boolean R(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void P() {
        if (this.v == null) {
            this.v = new j(super.getContext(), this);
            if (R(getHost())) {
                this.w = M6.e(super.getContext());
            } else {
                this.w = true;
            }
        }
    }

    public final void Q() {
        if (R(getHost()) && !this.z) {
            this.z = true;
            ForgotPasswordDialogFragment forgotPasswordDialogFragment = (ForgotPasswordDialogFragment) this;
            forgotPasswordDialogFragment.q = ((com.quizlet.quizletandroid.j) ((g) d())).d.a();
            forgotPasswordDialogFragment.A = com.quizlet.login.common.util.a.a;
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.x == null) {
            synchronized (this.y) {
                try {
                    if (this.x == null) {
                        this.x = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.x.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.w) {
            return null;
        }
        P();
        return this.v;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !R(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        P();
        Q();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.z;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.v;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        P();
        Q();
    }
}
