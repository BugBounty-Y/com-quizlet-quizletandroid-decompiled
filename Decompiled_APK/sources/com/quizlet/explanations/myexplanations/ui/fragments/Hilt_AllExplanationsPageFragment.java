package com.quizlet.explanations.myexplanations.ui.fragments;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.onetrust.otpublishers.headless.Internal.Helper.h;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes2.dex */
public abstract class Hilt_AllExplanationsPageFragment extends BaseExplanationsPageFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j f;
    public boolean g;
    public volatile f h;
    public final Object i = new Object();
    public boolean j = false;

    public static boolean V(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void T() {
        if (this.f == null) {
            this.f = new j(super.getContext(), this);
            if (V(getHost())) {
                this.g = M6.e(super.getContext());
            } else {
                this.g = true;
            }
        }
    }

    public final void U() {
        if (V(getHost()) && !this.j) {
            this.j = true;
            AllExplanationsPageFragment allExplanationsPageFragment = (AllExplanationsPageFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((b) d());
            allExplanationsPageFragment.a = jVar.d.a();
            allExplanationsPageFragment.b = jVar.b.S0();
            allExplanationsPageFragment.k = new assistantMode.utils.studiableMetadata.b(24);
            allExplanationsPageFragment.l = new h(24);
            allExplanationsPageFragment.m = new com.quizlet.shared.usecase.folderstudymaterials.b(24);
            allExplanationsPageFragment.n = new com.quizlet.shared.usecase.folderstudymaterials.a(24);
            allExplanationsPageFragment.o = new com.google.mlkit.common.sdkinternal.model.a(24);
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.h == null) {
            synchronized (this.i) {
                try {
                    if (this.h == null) {
                        this.h = new f(this);
                    }
                } finally {
                }
            }
        }
        return this.h.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.g) {
            return null;
        }
        T();
        return this.f;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !V(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        T();
        U();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.j;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.f;
        R6.b(jVar == null || f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        T();
        U();
    }
}
