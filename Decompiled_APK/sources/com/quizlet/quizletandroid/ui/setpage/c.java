package com.quizlet.quizletandroid.ui.setpage;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.baseui.base.BaseDaggerBottomSheetDialogFragment;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class c<T extends androidx.viewbinding.a> extends BaseDaggerBottomSheetDialogFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j s;
    public boolean t;
    public volatile dagger.hilt.android.internal.managers.f u;
    public final Object v = new Object();
    public boolean w = false;

    public static boolean T(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void R() {
        if (this.s == null) {
            this.s = new j(super.getContext(), this);
            if (T(getHost())) {
                this.t = M6.e(super.getContext());
            } else {
                this.t = true;
            }
        }
    }

    public final void S() {
        if (T(getHost()) && !this.w) {
            this.w = true;
            g gVar = (g) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((h) d());
            gVar.r = jVar.d.a();
            gVar.x = jVar.b.Z();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.u == null) {
            synchronized (this.v) {
                try {
                    if (this.u == null) {
                        this.u = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.u.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.t) {
            return null;
        }
        R();
        return this.s;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !T(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseDaggerBottomSheetDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
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
        return this.w;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.s;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        R();
        S();
    }
}
