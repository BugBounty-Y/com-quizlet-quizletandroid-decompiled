package com.quizlet.quizletandroid.ui.setcreation.fragments;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import androidx.viewbinding.a;
import com.google.android.gms.internal.ads.C2824xF;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.quizletandroid.u;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class Hilt_EditSetFragment<T extends androidx.viewbinding.a> extends BaseFragment<T> implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public dagger.hilt.android.internal.managers.j e;
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
            this.e = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
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
            EditSetFragment editSetFragment = (EditSetFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((j) d());
            editSetFragment.a = jVar.d.a();
            u uVar = jVar.b;
            editSetFragment.b = uVar.S0();
            editSetFragment.k = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
            editSetFragment.l = uVar.m0();
            editSetFragment.m = com.quizlet.featuregate.injection.a.j();
            editSetFragment.n = (com.quizlet.quizletandroid.util.f) uVar.a0.get();
            editSetFragment.o = (com.quizlet.qutils.image.loading.a) uVar.s.get();
            editSetFragment.p = (com.quizlet.quizletandroid.ui.setcreation.tracking.c) jVar.e.get();
            editSetFragment.q = new androidx.camera.camera2.internal.compat.workaround.e(16, false);
            editSetFragment.r = uVar.c1();
            assistantMode.utils.studiableMetadata.b imageUploadFeature = new assistantMode.utils.studiableMetadata.b(26);
            assistantMode.utils.studiableMetadata.b imageUploadFeature2 = new assistantMode.utils.studiableMetadata.b(26);
            Intrinsics.checkNotNullParameter(imageUploadFeature2, "imageUploadFeature");
            com.google.android.material.floatingactionbutton.c imageUploadUpsellFeature = new com.google.android.material.floatingactionbutton.c(imageUploadFeature2);
            androidx.work.impl.model.c userProps = uVar.m0();
            com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
            Intrinsics.checkNotNullParameter(imageUploadFeature, "imageUploadFeature");
            Intrinsics.checkNotNullParameter(imageUploadUpsellFeature, "imageUploadUpsellFeature");
            Intrinsics.checkNotNullParameter(userProps, "userProps");
            Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
            Intrinsics.checkNotNullParameter(imageUploadFeature, "imageUploadFeature");
            Intrinsics.checkNotNullParameter(imageUploadUpsellFeature, "imageUploadUpsellFeature");
            Intrinsics.checkNotNullParameter(userProps, "userProps");
            Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
            com.quizlet.data.repository.explanations.question.a aVar = new com.quizlet.data.repository.explanations.question.a();
            aVar.a = imageUploadFeature;
            aVar.b = imageUploadUpsellFeature;
            aVar.c = userProps;
            aVar.d = loggedInUserManager;
            editSetFragment.s = aVar;
            com.quizlet.infra.legacysyncengine.managers.i iVar = (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get();
            com.quizlet.quizletandroid.ui.common.images.capture.c createSetImageCache = new com.quizlet.quizletandroid.ui.common.images.capture.c();
            Intrinsics.checkNotNullParameter(createSetImageCache, "createSetImageCache");
            androidx.camera.camera2.internal.concurrent.a aVar2 = new androidx.camera.camera2.internal.concurrent.a(createSetImageCache);
            C2824xF c2824xF = new C2824xF();
            c2824xF.b = iVar;
            c2824xF.c = aVar2;
            editSetFragment.t = c2824xF;
            editSetFragment.u = new com.quizlet.quizletandroid.ui.common.images.capture.c();
            editSetFragment.v = (com.quizlet.richtext.rendering.c) uVar.o0.get();
            editSetFragment.w = new com.quizlet.quizletandroid.ui.setcreation.managers.n(uVar.D0());
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
    public void onAttach(Context context) {
        super.onAttach(context);
        Q();
        R();
    }

    @Override // androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.i;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.e;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        Q();
        R();
    }
}
