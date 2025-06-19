package com.quizlet.features.settings;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.compose.runtime.internal.d;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.assembly.compose.cards.c;
import com.quizlet.baseui.base.b;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class SettingsActivity extends b implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public static final /* synthetic */ int p = 0;
    public com.quizlet.login.authentication.login.a k;
    public volatile dagger.hilt.android.internal.managers.b l;
    public final Object m = new Object();
    public boolean n = false;
    public com.quizlet.quizletandroid.ui.debug.a o;

    public SettingsActivity() {
        addOnContextAvailableListener(new C0054j(this, 21));
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "SettingsFragment";
    }

    public final dagger.hilt.android.internal.managers.b J() {
        if (this.l == null) {
            synchronized (this.m) {
                try {
                    if (this.l == null) {
                        this.l = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.l;
    }

    public final void K(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = J().b();
            this.k = aVarB;
            if (aVarB.l()) {
                this.k.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return J().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        K(bundle);
        v.b(this, null, 3);
        j.a(this, new d(true, -401357467, new c(this, 19)));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.k;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.n;
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return 0;
    }
}
