package com.quizlet.quizletandroid.ui.setpage.terms;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.compose.material3.C0676l1;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.ads.C4641h;
import dagger.hilt.android.internal.managers.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class Hilt_TermListFragment extends RecyclerViewFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j s;
    public boolean t;
    public volatile dagger.hilt.android.internal.managers.f u;
    public final Object v = new Object();
    public boolean w = false;

    public static boolean Y(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void W() {
        if (this.s == null) {
            this.s = new j(super.getContext(), this);
            if (Y(getHost())) {
                this.t = M6.e(super.getContext());
            } else {
                this.t = true;
            }
        }
    }

    public final void X() {
        if (Y(getHost()) && !this.w) {
            this.w = true;
            TermListFragment termListFragment = (TermListFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((h) d());
            termListFragment.a = jVar.d.a();
            u uVar = jVar.b;
            termListFragment.b = uVar.S0();
            com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature = new com.quizlet.shared.usecase.studiableMetadata.a(25);
            Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
            termListFragment.x = new com.google.mlkit.vision.documentscanner.internal.c(globalAdFeature);
            androidx.work.impl.model.c cVarM0 = uVar.m0();
            C0676l1 c0676l1 = new C0676l1();
            com.google.mlkit.vision.documentscanner.internal.c cVar = new com.google.mlkit.vision.documentscanner.internal.c(uVar.v0);
            com.quizlet.ads.b bVarO0 = uVar.o0();
            C4636c adsizeCreator = new C4636c(new C4641h(3));
            Intrinsics.checkNotNullParameter(adsizeCreator, "adsizeCreator");
            termListFragment.y = new com.quizlet.quizletandroid.ui.common.ads.nativeads.module.c(cVarM0, c0676l1, new com.quizlet.quizletandroid.ui.common.ads.nativeads.module.f(cVar, bVarO0, new C4641h(1)));
            termListFragment.z = uVar.m0();
            termListFragment.A = com.quizlet.featuregate.injection.a.f();
            termListFragment.B = (SetPagePerformanceLogger) jVar.c.i.get();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.u == null) {
            synchronized (this.v) {
                try {
                    if (this.u == null) {
                        this.u = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.u.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.t) {
            return null;
        }
        W();
        return this.s;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !Y(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        W();
        X();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.w;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        j jVar = this.s;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        W();
        X();
    }
}
