package com.quizlet.quizletandroid.ui.group.classuser;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes3.dex */
public abstract class Hilt_ClassUserListFragment<T> extends ViewModelDataSourceRecyclerViewFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j t;
    public boolean u;
    public volatile f v;
    public final Object w = new Object();
    public boolean x = false;

    public static boolean d0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void b0() {
        if (this.t == null) {
            this.t = new j(super.getContext(), this);
            if (d0(getHost())) {
                this.u = M6.e(super.getContext());
            } else {
                this.u = true;
            }
        }
    }

    public final void c0() {
        if (d0(getHost()) && !this.x) {
            this.x = true;
            ClassUserListFragment classUserListFragment = (ClassUserListFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((b) d());
            classUserListFragment.a = jVar.d.a();
            u uVar = jVar.b;
            classUserListFragment.b = uVar.S0();
            classUserListFragment.y = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
            classUserListFragment.z = (d) uVar.Z.get();
            classUserListFragment.A = uVar.l0();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.v == null) {
            synchronized (this.w) {
                try {
                    if (this.v == null) {
                        this.v = new f(this);
                    }
                } finally {
                }
            }
        }
        return this.v.d();
    }

    @Override // androidx.fragment.app.Fragment
    public Context getContext() {
        if (super.getContext() == null && !this.u) {
            return null;
        }
        b0();
        return this.t;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public y0 getDefaultViewModelProviderFactory() {
        return !d0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        b0();
        c0();
    }

    @Override // androidx.fragment.app.Fragment
    public LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.t;
        R6.b(jVar == null || f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        b0();
        c0();
    }
}
