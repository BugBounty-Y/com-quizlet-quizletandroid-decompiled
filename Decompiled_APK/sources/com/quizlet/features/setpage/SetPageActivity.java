package com.quizlet.features.setpage;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class SetPageActivity extends r implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final e h1 = new e();
    public com.quizlet.login.authentication.login.a d1;
    public volatile dagger.hilt.android.internal.managers.b e1;
    public final Object f1 = new Object();
    public boolean g1 = false;

    public SetPageActivity() {
        addOnContextAvailableListener(new C0054j(this, 20));
    }

    public final dagger.hilt.android.internal.managers.b X() {
        if (this.e1 == null) {
            synchronized (this.f1) {
                try {
                    if (this.e1 == null) {
                        this.e1 = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.e1;
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return X().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.features.setpage.r, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = X().b();
            this.d1 = aVarB;
            if (aVarB.l()) {
                this.d1.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.features.setpage.r, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.d1;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.g1;
    }
}
