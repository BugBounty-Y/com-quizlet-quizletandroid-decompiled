package com.quizlet.quizletandroid.ui.group;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.interactor.t;
import com.quizlet.quizletandroid.u;
import dagger.hilt.android.internal.managers.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class Hilt_GroupFragment<T extends androidx.viewbinding.a> extends BaseFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public j e;
    public boolean f;
    public volatile dagger.hilt.android.internal.managers.f g;
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
            GroupFragment groupFragment = (GroupFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((h) d());
            groupFragment.a = jVar.d.a();
            u uVar = jVar.b;
            groupFragment.b = uVar.S0();
            groupFragment.j = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
            groupFragment.k = (EventLogger) uVar.l0.get();
            groupFragment.l = uVar.m0();
            groupFragment.m = (com.quizlet.infra.legacysyncengine.managers.h) uVar.f1.get();
            groupFragment.n = (IQuizletApiClient) uVar.O.get();
            groupFragment.o = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
            groupFragment.p = com.quizlet.featuregate.injection.a.j();
            groupFragment.q = com.quizlet.featuregate.injection.a.l();
            groupFragment.r = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
            groupFragment.s = uVar.l0();
            groupFragment.t = new com.quizlet.shared.usecase.srs.a(25);
            groupFragment.u = new com.google.android.material.floatingactionbutton.c(new com.quizlet.shared.usecase.srs.a(25));
            groupFragment.v = new com.quizlet.shared.usecase.srs.a(25);
            groupFragment.w = new com.quizlet.data.interactor.achievements.f((t) uVar.Y0.get());
            groupFragment.x = uVar.l();
            groupFragment.y = new com.quizlet.data.repository.user.a(new com.quizlet.data.interactor.course.a((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get()));
            com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
            Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
            groupFragment.z = new com.quizlet.quizletandroid.ui.common.adapter.c();
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.g == null) {
            synchronized (this.h) {
                try {
                    if (this.g == null) {
                        this.g = new dagger.hilt.android.internal.managers.f(this);
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
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        Q();
        R();
    }
}
