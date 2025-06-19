package com.quizlet.features.emailconfirmation.ui.activities;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import com.quizlet.quizletandroid.ui.group.GroupActivity;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;

/* loaded from: classes2.dex */
public abstract class l extends com.quizlet.baseui.base.b implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public final /* synthetic */ int k;
    public com.quizlet.login.authentication.login.a l;
    public volatile dagger.hilt.android.internal.managers.b m;
    public final Object n;
    public boolean o;

    public l(int i) {
        this.k = i;
        switch (i) {
            case 1:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new C0054j((MagicLinkConfirmationActivity) this, 7));
                break;
            case 2:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new C0054j((DeepLinkInterstitialActivity) this, 27));
                break;
            case 3:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new C0054j((GlobalNavigationActivity) this, 29));
                break;
            case 4:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((GroupActivity) this, 0));
                break;
            case 5:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((JoinContentToFolderActivity) this, 2));
                break;
            case 6:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((QuizletLiveDeepLinkInterstitialActivity) this, 4));
                break;
            case 7:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((ProfileActivity) this, 10));
                break;
            case 8:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((AddSetToClassActivity) this, 20));
                break;
            default:
                this.n = new Object();
                this.o = false;
                addOnContextAvailableListener(new C0054j((EmailConfirmationActivity) this, 6));
                break;
        }
    }

    private final dagger.hilt.android.internal.managers.b K() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    private final dagger.hilt.android.internal.managers.b L() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    private final dagger.hilt.android.internal.managers.b M() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    private final dagger.hilt.android.internal.managers.b N() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    private final dagger.hilt.android.internal.managers.b O() {
        if (this.m == null) {
            synchronized (this.n) {
                try {
                    if (this.m == null) {
                        this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.m;
    }

    public final dagger.hilt.android.internal.managers.b J() {
        switch (this.k) {
            case 0:
                if (this.m == null) {
                    synchronized (this.n) {
                        try {
                            if (this.m == null) {
                                this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.m;
            case 1:
                if (this.m == null) {
                    synchronized (this.n) {
                        try {
                            if (this.m == null) {
                                this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.m;
            case 2:
                if (this.m == null) {
                    synchronized (this.n) {
                        try {
                            if (this.m == null) {
                                this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.m;
            case 3:
                return K();
            case 4:
                return L();
            case 5:
                return M();
            case 6:
                return N();
            case 7:
                return O();
            default:
                if (this.m == null) {
                    synchronized (this.n) {
                        try {
                            if (this.m == null) {
                                this.m = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.m;
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.k) {
        }
        return J().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        switch (this.k) {
            case 0:
                ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
                if ((componentCallbacks2B instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) {
                    break;
                } else {
                    break;
                }
            case 1:
                ComponentCallbacks2 componentCallbacks2B2 = N6.b(getApplicationContext());
                if ((componentCallbacks2B2 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B2 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B2).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 2:
                ComponentCallbacks2 componentCallbacks2B3 = N6.b(getApplicationContext());
                if ((componentCallbacks2B3 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B3 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B3).u())) {
                    break;
                } else {
                    break;
                }
            case 3:
                ComponentCallbacks2 componentCallbacks2B4 = N6.b(getApplicationContext());
                if ((componentCallbacks2B4 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B4 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B4).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 4:
                ComponentCallbacks2 componentCallbacks2B5 = N6.b(getApplicationContext());
                if ((componentCallbacks2B5 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B5 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B5).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 5:
                ComponentCallbacks2 componentCallbacks2B6 = N6.b(getApplicationContext());
                if ((componentCallbacks2B6 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B6 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B6).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 6:
                ComponentCallbacks2 componentCallbacks2B7 = N6.b(getApplicationContext());
                if ((componentCallbacks2B7 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B7 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B7).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 7:
                ComponentCallbacks2 componentCallbacks2B8 = N6.b(getApplicationContext());
                if ((componentCallbacks2B8 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B8 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B8).u())) {
                    break;
                } else {
                    break;
                }
            default:
                ComponentCallbacks2 componentCallbacks2B9 = N6.b(getApplicationContext());
                if ((componentCallbacks2B9 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B9 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B9).u())) {
                    break;
                } else {
                    break;
                }
                break;
        }
        return super.getDefaultViewModelProviderFactory();
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        switch (this.k) {
            case 0:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB = J().b();
                    this.l = aVarB;
                    if (aVarB.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 1:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB2 = J().b();
                    this.l = aVarB2;
                    if (aVarB2.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 2:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB3 = J().b();
                    this.l = aVarB3;
                    if (aVarB3.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 3:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB4 = J().b();
                    this.l = aVarB4;
                    if (aVarB4.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 4:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB5 = J().b();
                    this.l = aVarB5;
                    if (aVarB5.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 5:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB6 = J().b();
                    this.l = aVarB6;
                    if (aVarB6.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 6:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB7 = J().b();
                    this.l = aVarB7;
                    if (aVarB7.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 7:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB8 = J().b();
                    this.l = aVarB8;
                    if (aVarB8.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            default:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB9 = J().b();
                    this.l = aVarB9;
                    if (aVarB9.l()) {
                        this.l.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        switch (this.k) {
            case 0:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar = this.l;
                if (aVar != null) {
                    aVar.b = null;
                    break;
                }
                break;
            case 1:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar2 = this.l;
                if (aVar2 != null) {
                    aVar2.b = null;
                    break;
                }
                break;
            case 2:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar3 = this.l;
                if (aVar3 != null) {
                    aVar3.b = null;
                    break;
                }
                break;
            case 3:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar4 = this.l;
                if (aVar4 != null) {
                    aVar4.b = null;
                    break;
                }
                break;
            case 4:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar5 = this.l;
                if (aVar5 != null) {
                    aVar5.b = null;
                    break;
                }
                break;
            case 5:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar6 = this.l;
                if (aVar6 != null) {
                    aVar6.b = null;
                    break;
                }
                break;
            case 6:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar7 = this.l;
                if (aVar7 != null) {
                    aVar7.b = null;
                    break;
                }
                break;
            case 7:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar8 = this.l;
                if (aVar8 != null) {
                    aVar8.b = null;
                    break;
                }
                break;
            default:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar9 = this.l;
                if (aVar9 != null) {
                    aVar9.b = null;
                    break;
                }
                break;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        switch (this.k) {
        }
        return this.o;
    }
}
