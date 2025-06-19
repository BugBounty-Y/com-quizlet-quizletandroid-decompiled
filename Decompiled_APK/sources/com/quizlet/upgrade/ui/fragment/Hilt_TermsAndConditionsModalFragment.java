package com.quizlet.upgrade.ui.fragment;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.M6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment;

/* loaded from: classes3.dex */
public abstract class Hilt_TermsAndConditionsModalFragment extends FullScreenConvertibleModalDialogFragment implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public dagger.hilt.android.internal.managers.j D;
    public boolean E;
    public volatile dagger.hilt.android.internal.managers.f F;
    public final Object G = new Object();
    public boolean H = false;

    public static boolean b0(Object obj) {
        if (obj instanceof dagger.hilt.internal.b) {
            return !(obj instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) obj).u();
        }
        return false;
    }

    public final void Y() {
        if (this.D == null) {
            this.D = new dagger.hilt.android.internal.managers.j(super.getContext(), this);
            if (b0(getHost())) {
                this.E = M6.e(super.getContext());
            } else {
                this.E = true;
            }
        }
    }

    public final void a0() {
        if (b0(getHost()) && !this.H) {
            this.H = true;
            TermsAndConditionsModalFragment termsAndConditionsModalFragment = (TermsAndConditionsModalFragment) this;
            com.quizlet.quizletandroid.j jVar = (com.quizlet.quizletandroid.j) ((c) d());
            termsAndConditionsModalFragment.q = jVar.d.a();
            com.quizlet.quizletandroid.util.g gVar = (com.quizlet.quizletandroid.util.g) jVar.b.B1.get();
            com.quizlet.quizletandroid.ui.webpages.a aVar = com.quizlet.quizletandroid.ui.webpages.a.a;
            termsAndConditionsModalFragment.I = new com.quizlet.quizletandroid.ui.navigationmanagers.i(gVar);
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.F == null) {
            synchronized (this.G) {
                try {
                    if (this.F == null) {
                        this.F = new dagger.hilt.android.internal.managers.f(this);
                    }
                } finally {
                }
            }
        }
        return this.F.d();
    }

    @Override // androidx.fragment.app.Fragment
    public final Context getContext() {
        if (super.getContext() == null && !this.E) {
            return null;
        }
        Y();
        return this.D;
    }

    @Override // androidx.fragment.app.Fragment, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return !b0(getHost()) ? super.getDefaultViewModelProviderFactory() : P6.b(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        super.onAttach(context);
        Y();
        a0();
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final LayoutInflater onGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = super.onGetLayoutInflater(bundle);
        return layoutInflaterOnGetLayoutInflater.cloneInContext(new dagger.hilt.android.internal.managers.j(layoutInflaterOnGetLayoutInflater, this));
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.H;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onAttach(Activity activity) {
        super.onAttach(activity);
        dagger.hilt.android.internal.managers.j jVar = this.D;
        R6.b(jVar == null || dagger.hilt.android.internal.managers.f.b(jVar) == activity, "onAttach called multiple times with different Context! Hilt Fragments should not be retained.", new Object[0]);
        Y();
        a0();
    }
}
