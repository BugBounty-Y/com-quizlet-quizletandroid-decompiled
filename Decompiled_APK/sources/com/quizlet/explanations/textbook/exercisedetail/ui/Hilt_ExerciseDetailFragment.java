package com.quizlet.explanations.textbook.exercisedetail.ui;

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
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.u;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes2.dex */
public abstract class Hilt_ExerciseDetailFragment<T extends androidx.viewbinding.a> extends BaseFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
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
            ExerciseDetailFragment exerciseDetailFragment = (ExerciseDetailFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((e) d());
            C4622e c4622e = jVar.d;
            exerciseDetailFragment.a = c4622e.a();
            u uVar = jVar.b;
            exerciseDetailFragment.b = uVar.S0();
            exerciseDetailFragment.j = new com.google.mlkit.common.sdkinternal.b(25);
            exerciseDetailFragment.k = new com.google.firebase.crashlytics.internal.settings.b((com.quizlet.qutils.image.loading.a) uVar.s.get());
            exerciseDetailFragment.l = new com.google.mlkit.common.internal.model.a(25);
            exerciseDetailFragment.m = new com.google.android.material.shape.e(25);
            exerciseDetailFragment.n = (com.quizlet.explanations.navigation.b) c4622e.X.get();
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
