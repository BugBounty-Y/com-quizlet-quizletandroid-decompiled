package com.quizlet.quizletandroid.ui.usersettings.fragments;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.u;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_CropImageFragment<T extends androidx.viewbinding.a> extends ChangeSettingsBaseFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j k;
    public boolean l;
    public volatile f m;
    public final Object n = new Object();
    public boolean o = false;

    public static boolean T(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void R() {
        if (this.k == null) {
            this.k = new j(super.getContext(), this);
            if (T(getHost())) {
                this.l = M6.e(super.getContext());
            } else {
                this.l = true;
            }
        }
    }

    public final void S() {
        if (T(getHost()) && !this.o) {
            this.o = true;
            CropImageFragment cropImageFragment = (CropImageFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((e) d());
            cropImageFragment.a = jVar.d.a();
            u uVar = jVar.b;
            cropImageFragment.b = uVar.S0();
            cropImageFragment.e = (IQuizletApiClient) uVar.O.get();
            cropImageFragment.f = (com.quizlet.quizletandroid.ui.usersettings.d) jVar.f.get();
            cropImageFragment.g = (EventLogger) uVar.l0.get();
            cropImageFragment.p = com.quizlet.featuregate.injection.a.l();
            cropImageFragment.q = com.quizlet.featuregate.injection.a.j();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new f(this);
                    }
                } finally {
                }
            }
        }
        return this.m.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.l) {
            return null;
        }
        R();
        return this.k;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !T(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        R();
        S();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.o;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.k;
        R6.b(jVar == null || f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        R();
        S();
    }
}
