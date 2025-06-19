package com.quizlet.features.notes.paywall;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.O;
import androidx.activity.P;
import androidx.activity.v;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.folders.composables.J;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class ScanNotesPaywallActivity extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public static final /* synthetic */ int k = 0;
    public com.quizlet.login.authentication.login.a d;
    public volatile dagger.hilt.android.internal.managers.b e;
    public final Object f = new Object();
    public boolean g = false;
    public final String h;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e i;
    public com.quizlet.quizletandroid.ui.navigationmanagers.f j;

    public ScanNotesPaywallActivity() {
        addOnContextAvailableListener(new C0054j(this, 11));
        this.h = "ScanNotesPaywallActivity";
        this.i = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(l.class), new c(this, 1), new c(this, 0), new c(this, 2));
    }

    public final i B() {
        return (i) this.i.getValue();
    }

    public final void C(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = z().b();
            this.d = aVarB;
            if (aVarB.l()) {
                this.d.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return z().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        C(bundle);
        int iA = com.quizlet.themes.extensions.a.a(this, R.attr.RefColorTwilight900);
        v.b(this, new P(iA, iA, 2, O.c), 2);
        androidx.activity.compose.j.a(this, new androidx.compose.runtime.internal.d(true, 1388487161, new b(this, 1)));
        ((l) B()).d.f(this, new com.quizlet.ads.ui.fragments.c(new J(this, 5)));
    }

    @Override // com.quizlet.baseui.base.c, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.d;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // com.quizlet.baseui.base.c
    public final String y() {
        return this.h;
    }

    public final dagger.hilt.android.internal.managers.b z() {
        if (this.e == null) {
            synchronized (this.f) {
                try {
                    if (this.e == null) {
                        this.e = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.e;
    }
}
