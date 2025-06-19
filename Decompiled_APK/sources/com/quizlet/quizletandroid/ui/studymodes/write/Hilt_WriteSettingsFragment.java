package com.quizlet.quizletandroid.ui.studymodes.write;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.quizletandroid.u;

/* loaded from: classes3.dex */
abstract class Hilt_WriteSettingsFragment extends n implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public dagger.hilt.android.internal.managers.j j;
    public boolean k;
    public volatile dagger.hilt.android.internal.managers.f l;
    public final Object m = new Object();
    public boolean n = false;

    public static boolean U(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void S() {
        if (this.j == null) {
            this.j = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
            if (U(getHost())) {
                this.k = M6.e(super.getContext());
            } else {
                this.k = true;
            }
        }
    }

    public final void T() {
        if (U(getHost()) && !this.n) {
            this.n = true;
            WriteSettingsFragment writeSettingsFragment = (WriteSettingsFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((o) d());
            writeSettingsFragment.a = jVar.d.a();
            u uVar = jVar.b;
            writeSettingsFragment.b = uVar.S0();
            writeSettingsFragment.i = (com.quizlet.quizletandroid.util.f) uVar.a0.get();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.l == null) {
            synchronized (this.m) {
                try {
                    if (this.l == null) {
                        this.l = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.l.d();
    }

    @Override // androidx.fragment.app.Fragment
    public Context getContext() {
        if (super.getContext() == null && !this.k) {
            return null;
        }
        S();
        return this.j;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public y0 getDefaultViewModelProviderFactory() {
        return !U(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        S();
        T();
    }

    @Override // androidx.fragment.app.Fragment
    public LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.j;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        S();
        T();
    }
}
