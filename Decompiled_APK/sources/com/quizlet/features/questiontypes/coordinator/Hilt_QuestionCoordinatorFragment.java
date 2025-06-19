package com.quizlet.features.questiontypes.coordinator;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.baseui.base.BaseFragment;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_QuestionCoordinatorFragment<T extends androidx.viewbinding.a> extends BaseFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j e;
    public boolean f;
    public volatile f g;
    public final Object h = new Object();
    public boolean i = false;

    public static boolean S(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void Q() {
        if (this.e == null) {
            this.e = new j(super.getContext(), this);
            if (S(getHost())) {
                this.f = M6.e(super.getContext());
            } else {
                this.f = true;
            }
        }
    }

    public final void R() {
        if (S(getHost()) && !this.i) {
            this.i = true;
            QuestionCoordinatorFragment questionCoordinatorFragment = (QuestionCoordinatorFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((b) d());
            questionCoordinatorFragment.a = jVar.d.a();
            questionCoordinatorFragment.b = jVar.b.S0();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.g == null) {
            synchronized (this.h) {
                try {
                    if (this.g == null) {
                        this.g = new f(this);
                    }
                } finally {
                }
            }
        }
        return this.g.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.f) {
            return null;
        }
        Q();
        return this.e;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !S(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        Q();
        R();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.i;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.e;
        R6.b(jVar == null || f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        Q();
        R();
    }
}
