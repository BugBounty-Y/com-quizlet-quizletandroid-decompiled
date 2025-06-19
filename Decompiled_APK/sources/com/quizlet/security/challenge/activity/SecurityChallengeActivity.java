package com.quizlet.security.challenge.activity;

import android.app.Activity;
import android.os.Bundle;
import androidx.activity.compose.j;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.lifecycle.p0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class SecurityChallengeActivity extends AbstractActivityC0055k implements dagger.hilt.internal.b {
    public com.quizlet.login.authentication.login.a c;
    public volatile dagger.hilt.android.internal.managers.b d;
    public final Object e = new Object();
    public boolean f = false;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e g;

    public SecurityChallengeActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.subject.c(this, 4));
        this.g = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.security.challenge.viewmodel.d.class), new d(this, 1), new d(this, 0), new d(this, 2));
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
        E.A(p0.h(this), null, null, new c(this, null), 3);
        j.a(this, new androidx.compose.runtime.internal.d(true, -238582026, new a(this, 1)));
        timber.log.c.a.o("Security Challenge launched", new Object[0]);
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
