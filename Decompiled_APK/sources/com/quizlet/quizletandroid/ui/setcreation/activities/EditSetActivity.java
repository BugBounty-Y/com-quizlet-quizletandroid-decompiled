package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;

/* loaded from: classes3.dex */
public class EditSetActivity extends d implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int M = 0;
    public com.quizlet.login.authentication.login.a I;
    public volatile dagger.hilt.android.internal.managers.b J;
    public final Object K = new Object();
    public boolean L = false;

    public EditSetActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 13));
    }

    public final dagger.hilt.android.internal.managers.b U() {
        if (this.J == null) {
            synchronized (this.K) {
                try {
                    if (this.J == null) {
                        this.J = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.J;
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return U().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.activities.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = U().b();
            this.I = aVarB;
            if (aVarB.l()) {
                this.I.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.activities.d, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.I;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.L;
    }
}
