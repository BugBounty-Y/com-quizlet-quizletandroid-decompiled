package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.braze.ui.contentcards.managers.BrazeContentCardsManager;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import dagger.hilt.android.internal.managers.j;

/* loaded from: classes3.dex */
public abstract class Hilt_ActivityCenterContentCardsFragment extends DaggerContentCardsFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j b;
    public boolean c;
    public volatile dagger.hilt.android.internal.managers.f d;
    public final Object e = new Object();
    public boolean f = false;

    public static boolean P(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void N() {
        if (this.b == null) {
            this.b = new j(super.getContext(), this);
            if (P(getHost())) {
                this.c = M6.e(super.getContext());
            } else {
                this.c = true;
            }
        }
    }

    public final void O() {
        if (P(getHost()) && !this.f) {
            this.f = true;
            ActivityCenterContentCardsFragment activityCenterContentCardsFragment = (ActivityCenterContentCardsFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((b) d());
            activityCenterContentCardsFragment.a = jVar.d.a();
            activityCenterContentCardsFragment.g = (com.quizlet.qutils.image.loading.a) jVar.b.s.get();
            BrazeContentCardsManager companion = BrazeContentCardsManager.Companion.getInstance();
            S6.c(companion);
            activityCenterContentCardsFragment.h = companion;
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.d == null) {
            synchronized (this.e) {
                try {
                    if (this.d == null) {
                        this.d = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.d.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.c) {
            return null;
        }
        N();
        return this.b;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !P(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        N();
        O();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.f;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.b;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        N();
        O();
    }
}
