package com.quizlet.features.infra.folder.create;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import dagger.hilt.android.internal.managers.f;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_CreateFolderModalFragment extends DialogInterfaceOnCancelListenerC1151t implements dagger.hilt.internal.b {
    public j q;
    public boolean r;
    public volatile f s;
    public final Object t = new Object();
    public boolean u = false;

    public final void P() {
        if (this.q == null) {
            this.q = new j(super.getContext(), this);
            this.r = M6.e(super.getContext());
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.s == null) {
            synchronized (this.t) {
                try {
                    if (this.s == null) {
                        this.s = new f(this);
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
        P();
        return this.q;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        P();
        if (this.u) {
            return;
        }
        this.u = true;
        ((d) d()).getClass();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.q;
        R6.b(jVar == null || f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        P();
        if (this.u) {
            return;
        }
        this.u = true;
        ((d) d()).getClass();
    }
}
