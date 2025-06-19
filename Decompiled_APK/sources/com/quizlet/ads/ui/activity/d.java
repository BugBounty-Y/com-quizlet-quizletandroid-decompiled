package com.quizlet.ads.ui.activity;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.os.Bundle;
import androidx.appcompat.app.C0054j;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.quizlet.baseui.base.f;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.managers.deeplinks.h;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.group.i;
import com.quizlet.quizletandroid.ui.preview.SetPreviewActivity;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetPermissionSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.InputPasswordActivity;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class d extends f implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a {
    public final /* synthetic */ int l;
    public com.quizlet.login.authentication.login.a m;
    public volatile dagger.hilt.android.internal.managers.b n;
    public final Object o;
    public boolean p;

    public d(int i) {
        this.l = i;
        switch (i) {
            case 1:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new C0054j((QuestionDetailActivity) this, 2));
                break;
            case 2:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new C0054j((TextbookActivity) this, 3));
                break;
            case 3:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new C0054j((DiagramOverviewActivity) this, 28));
                break;
            case 4:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((SetPreviewActivity) this, 9));
                break;
            case 5:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((QLiveQrCodeReaderActivity) this, 11));
                break;
            case 6:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((SearchActivity) this, 12));
                break;
            case 7:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((EditSetPermissionSelectionActivity) this, 16));
                break;
            case 8:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((InputPasswordActivity) this, 18));
                break;
            case 9:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((LearningAssistantActivity) this, 23));
                break;
            case 10:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((MatchActivity) this, 25));
                break;
            case 11:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((MatchSettingsActivity) this, 26));
                break;
            case 12:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new i((TestStudyModeActivity) this, 27));
                break;
            case 13:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.subject.c((WebViewActivity) this, 3));
                break;
            case 14:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.subject.c((UpgradeActivity) this, 5));
                break;
            default:
                this.o = new Object();
                this.p = false;
                addOnContextAvailableListener(new C0054j((AdsActivity) this, 1));
                break;
        }
    }

    private final dagger.hilt.android.internal.managers.b P() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b Q() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b R() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b S() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b T() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b U() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b V() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b W() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b X() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b Y() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    private final dagger.hilt.android.internal.managers.b Z() {
        if (this.n == null) {
            synchronized (this.o) {
                try {
                    if (this.n == null) {
                        this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.n;
    }

    public final dagger.hilt.android.internal.managers.b O() {
        switch (this.l) {
            case 0:
                if (this.n == null) {
                    synchronized (this.o) {
                        try {
                            if (this.n == null) {
                                this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.n;
            case 1:
                if (this.n == null) {
                    synchronized (this.o) {
                        try {
                            if (this.n == null) {
                                this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.n;
            case 2:
                if (this.n == null) {
                    synchronized (this.o) {
                        try {
                            if (this.n == null) {
                                this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.n;
            case 3:
                return P();
            case 4:
                return Q();
            case 5:
                return R();
            case 6:
                return S();
            case 7:
                return T();
            case 8:
                return U();
            case 9:
                return V();
            case 10:
                return W();
            case 11:
                return X();
            case 12:
                return Y();
            case 13:
                return Z();
            default:
                if (this.n == null) {
                    synchronized (this.o) {
                        try {
                            if (this.n == null) {
                                this.n = new dagger.hilt.android.internal.managers.b((Activity) this);
                            }
                        } finally {
                        }
                    }
                }
                return this.n;
        }
    }

    public void a0() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        if (componentCallbacks2B instanceof dagger.hilt.internal.b) {
            if ((!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u()) && !this.p) {
                this.p = true;
                WebViewActivity webViewActivity = (WebViewActivity) this;
                C4622e c4622e = (C4622e) ((com.quizlet.quizletandroid.ui.webpages.b) d());
                webViewActivity.c = c4622e.a();
                u uVar = c4622e.b;
                webViewActivity.e = uVar.Q0();
                webViewActivity.q = (com.quizlet.db.token.a) uVar.u.get();
                uVar.D0();
                webViewActivity.r = (com.quizlet.features.consent.onetrust.d) uVar.R0.get();
                com.quizlet.quizletandroid.deeplinks.a aVar = new com.quizlet.quizletandroid.deeplinks.a();
                com.quizlet.quizletandroid.deeplinks.a base36Converter = com.quizlet.quizletandroid.deeplinks.a.a;
                Intrinsics.checkNotNullParameter(base36Converter, "base36Converter");
                webViewActivity.s = new com.quizlet.data.repository.login.a(aVar, new com.quizlet.quizletandroid.deeplinks.a(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
                webViewActivity.t = new h();
            }
        }
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.l) {
        }
        return O().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        switch (this.l) {
            case 0:
                ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
                if ((componentCallbacks2B instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) {
                    break;
                } else {
                    break;
                }
                break;
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
                break;
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
            case 7:
                ComponentCallbacks2 componentCallbacks2B8 = N6.b(getApplicationContext());
                if ((componentCallbacks2B8 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B8 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B8).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 8:
                ComponentCallbacks2 componentCallbacks2B9 = N6.b(getApplicationContext());
                if ((componentCallbacks2B9 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B9 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B9).u())) {
                    break;
                } else {
                    break;
                }
            case 9:
                ComponentCallbacks2 componentCallbacks2B10 = N6.b(getApplicationContext());
                if ((componentCallbacks2B10 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B10 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B10).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 10:
                ComponentCallbacks2 componentCallbacks2B11 = N6.b(getApplicationContext());
                if ((componentCallbacks2B11 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B11 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B11).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 11:
                ComponentCallbacks2 componentCallbacks2B12 = N6.b(getApplicationContext());
                if ((componentCallbacks2B12 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B12 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B12).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 12:
                ComponentCallbacks2 componentCallbacks2B13 = N6.b(getApplicationContext());
                if ((componentCallbacks2B13 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B13 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B13).u())) {
                    break;
                } else {
                    break;
                }
                break;
            case 13:
                ComponentCallbacks2 componentCallbacks2B14 = N6.b(getApplicationContext());
                if ((componentCallbacks2B14 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B14 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B14).u())) {
                    break;
                } else {
                    break;
                }
            default:
                ComponentCallbacks2 componentCallbacks2B15 = N6.b(getApplicationContext());
                if ((componentCallbacks2B15 instanceof dagger.hilt.internal.b) && (!(componentCallbacks2B15 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B15).u())) {
                    break;
                } else {
                    break;
                }
                break;
        }
        return super.getDefaultViewModelProviderFactory();
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        switch (this.l) {
            case 0:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB = O().b();
                    this.m = aVarB;
                    if (aVarB.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 1:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB2 = O().b();
                    this.m = aVarB2;
                    if (aVarB2.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 2:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB3 = O().b();
                    this.m = aVarB3;
                    if (aVarB3.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 3:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB4 = O().b();
                    this.m = aVarB4;
                    if (aVarB4.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 4:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB5 = O().b();
                    this.m = aVarB5;
                    if (aVarB5.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 5:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB6 = O().b();
                    this.m = aVarB6;
                    if (aVarB6.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 6:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB7 = O().b();
                    this.m = aVarB7;
                    if (aVarB7.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 7:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB8 = O().b();
                    this.m = aVarB8;
                    if (aVarB8.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 8:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB9 = O().b();
                    this.m = aVarB9;
                    if (aVarB9.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 9:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB10 = O().b();
                    this.m = aVarB10;
                    if (aVarB10.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 10:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB11 = O().b();
                    this.m = aVarB11;
                    if (aVarB11.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 11:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB12 = O().b();
                    this.m = aVarB12;
                    if (aVarB12.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 12:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB13 = O().b();
                    this.m = aVarB13;
                    if (aVarB13.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            case 13:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB14 = O().b();
                    this.m = aVarB14;
                    if (aVarB14.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
            default:
                super.onCreate(bundle);
                if (getApplication() instanceof dagger.hilt.internal.b) {
                    com.quizlet.login.authentication.login.a aVarB15 = O().b();
                    this.m = aVarB15;
                    if (aVarB15.l()) {
                        this.m.b = getDefaultViewModelCreationExtras();
                        break;
                    }
                }
                break;
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onDestroy() {
        switch (this.l) {
            case 0:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar = this.m;
                if (aVar != null) {
                    aVar.b = null;
                    break;
                }
                break;
            case 1:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar2 = this.m;
                if (aVar2 != null) {
                    aVar2.b = null;
                    break;
                }
                break;
            case 2:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar3 = this.m;
                if (aVar3 != null) {
                    aVar3.b = null;
                    break;
                }
                break;
            case 3:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar4 = this.m;
                if (aVar4 != null) {
                    aVar4.b = null;
                    break;
                }
                break;
            case 4:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar5 = this.m;
                if (aVar5 != null) {
                    aVar5.b = null;
                    break;
                }
                break;
            case 5:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar6 = this.m;
                if (aVar6 != null) {
                    aVar6.b = null;
                    break;
                }
                break;
            case 6:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar7 = this.m;
                if (aVar7 != null) {
                    aVar7.b = null;
                    break;
                }
                break;
            case 7:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar8 = this.m;
                if (aVar8 != null) {
                    aVar8.b = null;
                    break;
                }
                break;
            case 8:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar9 = this.m;
                if (aVar9 != null) {
                    aVar9.b = null;
                    break;
                }
                break;
            case 9:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar10 = this.m;
                if (aVar10 != null) {
                    aVar10.b = null;
                    break;
                }
                break;
            case 10:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar11 = this.m;
                if (aVar11 != null) {
                    aVar11.b = null;
                    break;
                }
                break;
            case 11:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar12 = this.m;
                if (aVar12 != null) {
                    aVar12.b = null;
                    break;
                }
                break;
            case 12:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar13 = this.m;
                if (aVar13 != null) {
                    aVar13.b = null;
                    break;
                }
                break;
            case 13:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar14 = this.m;
                if (aVar14 != null) {
                    aVar14.b = null;
                    break;
                }
                break;
            default:
                super.onDestroy();
                com.quizlet.login.authentication.login.a aVar15 = this.m;
                if (aVar15 != null) {
                    aVar15.b = null;
                    break;
                }
                break;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public boolean u() {
        switch (this.l) {
        }
        return this.p;
    }
}
