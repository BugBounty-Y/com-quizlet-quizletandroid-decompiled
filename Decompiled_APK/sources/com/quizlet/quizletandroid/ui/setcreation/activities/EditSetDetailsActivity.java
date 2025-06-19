package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;

/* loaded from: classes3.dex */
public class EditSetDetailsActivity extends h implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int y = 0;
    public com.quizlet.login.authentication.login.a u;
    public volatile dagger.hilt.android.internal.managers.b v;
    public final Object w = new Object();
    public boolean x = false;

    public EditSetDetailsActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 14));
    }

    public final dagger.hilt.android.internal.managers.b P() {
        if (this.v == null) {
            synchronized (this.w) {
                try {
                    if (this.v == null) {
                        this.v = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.v;
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return P().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.quizletandroid.ui.setcreation.activities.h, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = P().b();
            this.u = aVarB;
            if (aVarB.l()) {
                this.u.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.u;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.x;
    }
}
