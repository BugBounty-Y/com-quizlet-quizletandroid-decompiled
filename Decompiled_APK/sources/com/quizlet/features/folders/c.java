package com.quizlet.features.folders;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.quizlet.features.setpage.NewSetPageActivity;

/* loaded from: classes3.dex */
public abstract class c extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public final /* synthetic */ int d;
    public com.quizlet.login.authentication.login.a e;
    public volatile dagger.hilt.android.internal.managers.b f;
    public final Object g;
    public boolean h;

    public c(int i) {
        this.d = i;
        switch (i) {
            case 1:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((NewSetPageActivity) this, 19));
                break;
            default:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((FolderActivity) this, 9));
                break;
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.d) {
        }
        return z().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        switch (this.d) {
            case 0:
                ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
                if ((componentCallbacks2B instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) {
                    break;
                } else {
                    break;
                }
            default:
                ComponentCallbacks2 componentCallbacks2B2 = N6.b(getApplicationContext());
                if ((componentCallbacks2B2 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B2 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B2).u())) {
                    break;
                } else {
                    break;
                }
                break;
        }
        return super.getDefaultViewModelProviderFactory();
    }

    @Override // com.quizlet.baseui.base.c, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        switch (this.d) {
            case 0:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB = z().b();
                    this.e = aVarB;
                    if (aVarB.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            default:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB2 = z().b();
                    this.e = aVarB2;
                    if (aVarB2.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
        }
    }

    @Override // com.quizlet.baseui.base.c, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        switch (this.d) {
            case 0:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar = this.e;
                if (aVar != null) {
                    aVar.b = null;
                    break;
                }
                break;
            default:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar2 = this.e;
                if (aVar2 != null) {
                    aVar2.b = null;
                    break;
                }
                break;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        switch (this.d) {
        }
        return this.h;
    }

    public final dagger.hilt.android.internal.managers.b z() {
        switch (this.d) {
            case 0:
                if (this.f == null) {
                    synchronized (this.g) {
                        try {
                            if (this.f == null) {
                                this.f = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.f;
            default:
                if (this.f == null) {
                    synchronized (this.g) {
                        try {
                            if (this.f == null) {
                                this.f = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.f;
        }
    }
}
