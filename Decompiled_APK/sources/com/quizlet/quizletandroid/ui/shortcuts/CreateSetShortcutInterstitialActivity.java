package com.quizlet.quizletandroid.ui.shortcuts;

import android.app.Activity;
import android.os.Bundle;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.quizletandroid.k;
import com.quizlet.quizletandroid.ui.common.ads.G;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.quizletandroid.ui.login.z;
import io.reactivex.rxjava3.internal.operators.observable.C4885d;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class CreateSetShortcutInterstitialActivity extends AbstractActivityC0055k implements dagger.hilt.internal.b {
    public com.quizlet.login.authentication.login.a c;
    public volatile dagger.hilt.android.internal.managers.b d;
    public final Object e = new Object();
    public boolean f = false;
    public d g;

    public CreateSetShortcutInterstitialActivity() {
        addOnContextAvailableListener(new i(this, 22));
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return x().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        y(bundle);
        d dVar = this.g;
        if (dVar == null) {
            Intrinsics.m("loggedInUserManager");
            throw null;
        }
        k kVar = new k(this, dVar);
        io.reactivex.rxjava3.subjects.d dVar2 = dVar.l;
        dVar2.getClass();
        C4885d c4885dJ = new C4887f(dVar2, 1).j();
        Intrinsics.checkNotNullExpressionValue(c4885dJ, "firstOrError(...)");
        B7.b(c4885dJ, new z(9), new G(kVar, 16));
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.c;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    public final dagger.hilt.android.internal.managers.b x() {
        if (this.d == null) {
            synchronized (this.e) {
                try {
                    if (this.d == null) {
                        this.d = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.d;
    }

    public final void y(Bundle bundle) {
        super.onCreate(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = x().b();
            this.c = aVarB;
            if (aVarB.l()) {
                this.c.b = getDefaultViewModelCreationExtras();
            }
        }
    }
}
