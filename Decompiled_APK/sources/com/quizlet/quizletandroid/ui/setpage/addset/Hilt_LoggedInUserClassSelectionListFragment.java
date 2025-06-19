package com.quizlet.quizletandroid.ui.setpage.addset;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.profile.UserClassListFragment;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_LoggedInUserClassSelectionListFragment extends UserClassListFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j v;
    public boolean w;
    public volatile dagger.hilt.android.internal.managers.f x;
    public final Object y = new Object();
    public boolean z = false;

    public static boolean i0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
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

    public final void g0() {
        if (this.v == null) {
            this.v = new j(super.getContext(), this);
            if (i0(getHost())) {
                this.w = M6.e(super.getContext());
            } else {
                this.w = true;
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.w) {
            return null;
        }
        g0();
        return this.v;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !i0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    public final void h0() {
        if (i0(getHost()) && !this.z) {
            this.z = true;
            LoggedInUserClassSelectionListFragment loggedInUserClassSelectionListFragment = (LoggedInUserClassSelectionListFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((e) d());
            C4622e c4622e = jVar.d;
            loggedInUserClassSelectionListFragment.a = c4622e.a();
            u uVar = jVar.b;
            loggedInUserClassSelectionListFragment.b = uVar.S0();
            loggedInUserClassSelectionListFragment.C = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
            loggedInUserClassSelectionListFragment.D = com.quizlet.featuregate.injection.a.j();
            c4622e.e();
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        g0();
        h0();
    }

    @Override // androidx.fragment.app.Fragment
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
        g0();
        h0();
    }
}
