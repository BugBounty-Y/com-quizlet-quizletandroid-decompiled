package com.quizlet.quizletandroid.ui.group.addclassset;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.quizletandroid.u;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
abstract class Hilt_StudiedUserSetListFragment extends AddToClassSetListFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j B;
    public boolean C;
    public volatile dagger.hilt.android.internal.managers.f D;
    public final Object E = new Object();
    public boolean F = false;

    public static boolean e0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void c0() {
        if (this.B == null) {
            this.B = new j(super.getContext(), this);
            if (e0(getHost())) {
                this.C = M6.e(super.getContext());
            } else {
                this.C = true;
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.D == null) {
            synchronized (this.E) {
                try {
                    if (this.D == null) {
                        this.D = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.D.d();
    }

    public final void d0() {
        if (e0(getHost()) && !this.F) {
            this.F = true;
            StudiedUserSetListFragment studiedUserSetListFragment = (StudiedUserSetListFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((g) d());
            studiedUserSetListFragment.a = jVar.d.a();
            u uVar = jVar.b;
            studiedUserSetListFragment.b = uVar.S0();
            studiedUserSetListFragment.x = uVar.e1();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public Context getContext() {
        if (super.getContext() == null && !this.C) {
            return null;
        }
        c0();
        return this.B;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public y0 getDefaultViewModelProviderFactory() {
        return !e0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.quizletandroid.ui.group.addclassset.AddToClassSetListFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        c0();
        d0();
    }

    @Override // androidx.fragment.app.Fragment
    public LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // androidx.fragment.app.Fragment
    public void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.B;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        c0();
        d0();
    }
}
