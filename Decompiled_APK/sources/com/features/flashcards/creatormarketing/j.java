package com.features.flashcards.creatormarketing;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.eventlogger.EventLogger;

/* loaded from: classes2.dex */
public abstract class j extends DialogInterfaceOnCancelListenerC1151t implements dagger.hilt.internal.b {
    public dagger.hilt.android.internal.managers.j q;
    public boolean r;
    public volatile dagger.hilt.android.internal.managers.f s;
    public final Object t = new Object();
    public boolean u = false;

    public final void P() {
        if (this.q == null) {
            this.q = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
            this.r = M6.e(super.getContext());
        }
    }

    public final void Q() {
        if (this.u) {
            return;
        }
        this.u = true;
        ((f) this).w = new h((EventLogger) ((com.quizlet.quizletandroid.j) ((g) d())).b.l0.get(), 0);
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
        Q();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.q;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        P();
        Q();
    }
}
