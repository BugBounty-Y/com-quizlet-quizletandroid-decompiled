package com.quizlet.quizletandroid.ui.qrcodes;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.baseui.base.BaseViewBindingDialogFragment;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class a<T extends androidx.viewbinding.a> extends BaseViewBindingDialogFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j w;
    public boolean x;
    public volatile dagger.hilt.android.internal.managers.f y;
    public final Object z = new Object();
    public boolean A = false;

    public static boolean T(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void R() {
        if (this.w == null) {
            this.w = new j(super.getContext(), this);
            if (T(getHost())) {
                this.x = M6.e(super.getContext());
            } else {
                this.x = true;
            }
        }
    }

    public final void S() {
        if (T(getHost()) && !this.A) {
            this.A = true;
            ((f) this).q = ((com.quizlet.quizletandroid.j) ((g) d())).d.a();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.y == null) {
            synchronized (this.z) {
                try {
                    if (this.y == null) {
                        this.y = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.y.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.x) {
            return null;
        }
        R();
        return this.w;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !T(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        R();
        S();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.A;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.w;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        R();
        S();
    }
}
