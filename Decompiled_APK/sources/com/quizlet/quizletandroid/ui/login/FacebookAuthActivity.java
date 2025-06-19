package com.quizlet.quizletandroid.ui.login;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.lifecycle.y0;
import com.facebook.internal.C1553h;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public class FacebookAuthActivity extends AbstractActivityC0055k implements dagger.hilt.internal.b {
    public static final /* synthetic */ int j = 0;
    public com.quizlet.login.authentication.login.a c;
    public volatile dagger.hilt.android.internal.managers.b d;
    public final Object e = new Object();
    public boolean f = false;
    public com.quizlet.data.interactor.achievements.f g;
    public C1553h h;
    public boolean i;

    public FacebookAuthActivity() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i(this, 6));
        this.i = false;
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return x().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        return P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        this.h.a(i, i2, intent);
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        y(bundle);
        setTitle((CharSequence) null);
        com.quizlet.data.interactor.achievements.f fVar = this.g;
        i onReady = new i(this, 1);
        fVar.getClass();
        Intrinsics.checkNotNullParameter(onReady, "onReady");
        ((com.quizlet.facebook.b) fVar.b).a(new com.quizlet.facebook.a(0, onReady));
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.c;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() throws PackageManager.NameNotFoundException {
        super.onStart();
        if (this.i) {
            return;
        }
        this.i = true;
        com.quizlet.data.interactor.achievements.f fVar = this.g;
        i onReady = new i(this, 0);
        fVar.getClass();
        Intrinsics.checkNotNullParameter(onReady, "onReady");
        ((com.quizlet.facebook.b) fVar.b).a(new com.quizlet.facebook.a(0, onReady));
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
