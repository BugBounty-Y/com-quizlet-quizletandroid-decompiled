package com.quizlet.quizletandroid.ui.login;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;

/* loaded from: classes3.dex */
public abstract class Hilt_OldNativeSignupFragment extends BaseSignupFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public dagger.hilt.android.internal.managers.j q;
    public boolean r;
    public volatile dagger.hilt.android.internal.managers.f s;
    public final Object t = new Object();
    public boolean u = false;

    public static boolean b0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void Y() {
        if (this.q == null) {
            this.q = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
            if (b0(getHost())) {
                this.r = M6.e(super.getContext());
            } else {
                this.r = true;
            }
        }
    }

    public final void a0() {
        if (b0(getHost()) && !this.u) {
            this.u = true;
            OldNativeSignupFragment oldNativeSignupFragment = (OldNativeSignupFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((o) d());
            oldNativeSignupFragment.a = jVar.d.a();
            com.quizlet.quizletandroid.u uVar = jVar.b;
            oldNativeSignupFragment.b = uVar.S0();
            oldNativeSignupFragment.e = (com.quizlet.quizletandroid.managers.g) uVar.Z0.get();
            oldNativeSignupFragment.f = com.quizlet.featuregate.injection.a.j();
            oldNativeSignupFragment.g = new androidx.work.impl.model.v(uVar.g1(), com.quizlet.quizletandroid.u.v());
            oldNativeSignupFragment.h = uVar.f1();
            oldNativeSignupFragment.i = com.quizlet.time.b.a;
            oldNativeSignupFragment.j = com.quizlet.qutils.string.c.a;
            oldNativeSignupFragment.k = com.quizlet.uicommon.util.tooltip.a.a;
            oldNativeSignupFragment.v = uVar.h1();
            oldNativeSignupFragment.w = (com.quizlet.data.connectivity.a) uVar.X.get();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.s == null) {
            synchronized (this.t) {
                try {
                    if (this.s == null) {
                        this.s = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.s.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.r) {
            return null;
        }
        Y();
        return this.q;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !b0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        Y();
        a0();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.u;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.q;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        Y();
        a0();
    }
}
