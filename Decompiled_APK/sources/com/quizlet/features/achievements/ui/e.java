package com.quizlet.features.achievements.ui;

import android.app.Activity;
import android.os.Bundle;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.blocks.GamesActivity;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.features.userprofile.ui.UserProfileActivity;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.LearnSettingsActivity;
import com.quizlet.quizletandroid.ui.subject.SubjectCategoryActivity;

/* loaded from: classes2.dex */
public abstract class e extends com.quizlet.baseui.base.c implements dagger.hilt.internal.b {
    public final /* synthetic */ int d;
    public com.quizlet.login.authentication.login.a e;
    public volatile dagger.hilt.android.internal.managers.b f;
    public final Object g;
    public boolean h;

    public e(int i) {
        this.d = i;
        switch (i) {
            case 1:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((GamesActivity) this, 5));
                break;
            case 2:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((FlashcardsActivity) this, 8));
                break;
            case 3:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((UserProfileActivity) this, 23));
                break;
            case 4:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((LoginNavActivity) this, 24));
                break;
            case 5:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new i((LearnSettingsActivity) this, 24));
                break;
            case 6:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.subject.c((SubjectCategoryActivity) this, 0));
                break;
            default:
                this.g = new Object();
                this.h = false;
                addOnContextAvailableListener(new C0054j((AchievementsActivity) this, 4));
                break;
        }
    }

    private final dagger.hilt.android.internal.managers.b B() {
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

    private final dagger.hilt.android.internal.managers.b C() {
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

    private final dagger.hilt.android.internal.managers.b D() {
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

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.d) {
        }
        return z().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        switch (this.d) {
        }
        return P6.a(this, super.getDefaultViewModelProviderFactory());
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
            case 1:
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
            case 2:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB3 = z().b();
                    this.e = aVarB3;
                    if (aVarB3.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 3:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB4 = z().b();
                    this.e = aVarB4;
                    if (aVarB4.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 4:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB5 = z().b();
                    this.e = aVarB5;
                    if (aVarB5.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 5:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB6 = z().b();
                    this.e = aVarB6;
                    if (aVarB6.l()) {
                        this.e.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            default:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB7 = z().b();
                    this.e = aVarB7;
                    if (aVarB7.l()) {
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
            case 1:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar2 = this.e;
                if (aVar2 != null) {
                    aVar2.b = null;
                    break;
                }
                break;
            case 2:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar3 = this.e;
                if (aVar3 != null) {
                    aVar3.b = null;
                    break;
                }
                break;
            case 3:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar4 = this.e;
                if (aVar4 != null) {
                    aVar4.b = null;
                    break;
                }
                break;
            case 4:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar5 = this.e;
                if (aVar5 != null) {
                    aVar5.b = null;
                    break;
                }
                break;
            case 5:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar6 = this.e;
                if (aVar6 != null) {
                    aVar6.b = null;
                    break;
                }
                break;
            default:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar7 = this.e;
                if (aVar7 != null) {
                    aVar7.b = null;
                    break;
                }
                break;
        }
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
            case 1:
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
            case 2:
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
            case 3:
                return B();
            case 4:
                return C();
            case 5:
                return D();
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
