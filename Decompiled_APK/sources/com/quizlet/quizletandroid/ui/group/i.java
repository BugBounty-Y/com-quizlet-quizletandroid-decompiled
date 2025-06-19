package com.quizlet.quizletandroid.ui.group;

import android.content.ComponentCallbacks2;
import android.content.Context;
import android.content.SharedPreferences;
import android.hardware.camera2.CameraManager;
import android.os.Handler;
import androidx.activity.s;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.work.impl.model.l;
import com.braze.Braze;
import com.comscore.streaming.EventType;
import com.facebook.internal.C1553h;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.mlkit_vision_barcode.M7;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.quizletandroid.C4595c;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.C4624g;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.group.addclassset.AddClassSetActivity;
import com.quizlet.quizletandroid.ui.joincontenttofolder.JoinContentToFolderActivity;
import com.quizlet.quizletandroid.ui.live.QuizletLiveActivity;
import com.quizlet.quizletandroid.ui.live.QuizletLiveDeepLinkInterstitialActivity;
import com.quizlet.quizletandroid.ui.live.interstitial.QuizletLiveInterstitialActivity;
import com.quizlet.quizletandroid.ui.login.FacebookAuthActivity;
import com.quizlet.quizletandroid.ui.login.OldSignupActivity;
import com.quizlet.quizletandroid.ui.login.j;
import com.quizlet.quizletandroid.ui.login.p;
import com.quizlet.quizletandroid.ui.onboarding.ui.ServerDrivenOnboardingActivity;
import com.quizlet.quizletandroid.ui.preview.SetPreviewActivity;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetDetailsActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetPermissionSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditTermImagePreviewActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.InputPasswordActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.ScanDocumentActivity;
import com.quizlet.quizletandroid.ui.setcreation.activities.k;
import com.quizlet.quizletandroid.ui.setcreation.activities.m;
import com.quizlet.quizletandroid.ui.setcreation.activities.q;
import com.quizlet.quizletandroid.ui.setcreation.managers.v;
import com.quizlet.quizletandroid.ui.setpage.addset.AddSetToClassActivity;
import com.quizlet.quizletandroid.ui.sharereceiver.ShareSheetReceiverActivity;
import com.quizlet.quizletandroid.ui.shortcuts.CreateSetShortcutInterstitialActivity;
import com.quizlet.quizletandroid.ui.studymodes.assistant.LearningAssistantActivity;
import com.quizlet.quizletandroid.ui.studymodes.assistant.n;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.LearnSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.settings.MatchSettingsActivity;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteSettingsActivity;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements androidx.activity.contextaware.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractActivityC0055k b;

    public /* synthetic */ i(AbstractActivityC0055k abstractActivityC0055k, int i) {
        this.a = i;
        this.b = abstractActivityC0055k;
    }

    @Override // androidx.activity.contextaware.b
    public final void a(s sVar) {
        AbstractActivityC0055k abstractActivityC0055k = this.b;
        switch (this.a) {
            case 0:
                GroupActivity groupActivity = (GroupActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B = N6.b(groupActivity.getApplicationContext());
                if (componentCallbacks2B instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u()) && !groupActivity.o) {
                        groupActivity.o = true;
                        C4622e c4622e = (C4622e) ((b) groupActivity.d());
                        groupActivity.c = c4622e.a();
                        u uVar = c4622e.b;
                        groupActivity.e = uVar.Q0();
                        groupActivity.p = (EventLogger) uVar.l0.get();
                        groupActivity.q = (com.quizlet.utmhelper.c) c4622e.o.get();
                        break;
                    }
                }
                break;
            case 1:
                AddClassSetActivity addClassSetActivity = (AddClassSetActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B2 = N6.b(addClassSetActivity.getApplicationContext());
                if (componentCallbacks2B2 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B2 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B2).u()) && !addClassSetActivity.o) {
                        addClassSetActivity.o = true;
                        C4622e c4622e2 = (C4622e) ((com.quizlet.quizletandroid.ui.group.addclassset.b) addClassSetActivity.d());
                        addClassSetActivity.c = c4622e2.a();
                        u uVar2 = c4622e2.b;
                        addClassSetActivity.e = uVar2.Q0();
                        addClassSetActivity.q = (com.quizlet.infra.legacysyncengine.net.f) uVar2.U.get();
                        addClassSetActivity.r = (com.quizlet.infra.legacysyncengine.managers.d) uVar2.Z.get();
                        addClassSetActivity.s = new androidx.compose.foundation.text.input.internal.u((com.quizlet.infra.legacysyncengine.net.c) uVar2.Q.get());
                        addClassSetActivity.t = uVar2.l();
                        break;
                    }
                }
                break;
            case 2:
                JoinContentToFolderActivity joinContentToFolderActivity = (JoinContentToFolderActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B3 = N6.b(joinContentToFolderActivity.getApplicationContext());
                if (componentCallbacks2B3 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B3 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B3).u()) && !joinContentToFolderActivity.o) {
                        joinContentToFolderActivity.o = true;
                        C4622e c4622e3 = (C4622e) ((com.quizlet.quizletandroid.ui.joincontenttofolder.f) joinContentToFolderActivity.d());
                        joinContentToFolderActivity.c = c4622e3.a();
                        joinContentToFolderActivity.e = c4622e3.b.Q0();
                        joinContentToFolderActivity.p = c4622e3.e();
                        break;
                    }
                }
                break;
            case 3:
                ((QuizletLiveActivity) abstractActivityC0055k).a0();
                break;
            case 4:
                QuizletLiveDeepLinkInterstitialActivity quizletLiveDeepLinkInterstitialActivity = (QuizletLiveDeepLinkInterstitialActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B4 = N6.b(quizletLiveDeepLinkInterstitialActivity.getApplicationContext());
                if (componentCallbacks2B4 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B4 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B4).u()) && !quizletLiveDeepLinkInterstitialActivity.o) {
                        quizletLiveDeepLinkInterstitialActivity.o = true;
                        C4622e c4622e4 = (C4622e) ((com.quizlet.quizletandroid.ui.live.e) quizletLiveDeepLinkInterstitialActivity.d());
                        quizletLiveDeepLinkInterstitialActivity.c = c4622e4.a();
                        u uVar3 = c4622e4.b;
                        quizletLiveDeepLinkInterstitialActivity.e = uVar3.Q0();
                        quizletLiveDeepLinkInterstitialActivity.p = new androidx.work.impl.model.e(27);
                        quizletLiveDeepLinkInterstitialActivity.q = new l(new com.quizlet.infra.legacysyncengine.managers.g(uVar3.q()));
                        quizletLiveDeepLinkInterstitialActivity.r = (com.quizlet.infra.legacysyncengine.managers.d) uVar3.Z.get();
                        break;
                    }
                }
                break;
            case 5:
                QuizletLiveInterstitialActivity quizletLiveInterstitialActivity = (QuizletLiveInterstitialActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B5 = N6.b(quizletLiveInterstitialActivity.getApplicationContext());
                if (componentCallbacks2B5 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B5 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B5).u()) && !quizletLiveInterstitialActivity.o) {
                        quizletLiveInterstitialActivity.o = true;
                        C4622e c4622e5 = (C4622e) ((com.quizlet.quizletandroid.ui.live.interstitial.b) quizletLiveInterstitialActivity.d());
                        quizletLiveInterstitialActivity.c = c4622e5.a();
                        u uVar4 = c4622e5.b;
                        quizletLiveInterstitialActivity.e = uVar4.Q0();
                        quizletLiveInterstitialActivity.p = new com.quizlet.data.repository.classmembership.c((com.quizlet.infra.legacysyncengine.managers.d) uVar4.Z.get(), uVar4.p0());
                        break;
                    }
                }
                break;
            case 6:
                FacebookAuthActivity facebookAuthActivity = (FacebookAuthActivity) abstractActivityC0055k;
                if (!facebookAuthActivity.f) {
                    facebookAuthActivity.f = true;
                    facebookAuthActivity.g = ((C4622e) ((j) facebookAuthActivity.d())).b.D();
                    facebookAuthActivity.h = new C1553h();
                    break;
                }
                break;
            case 7:
                OldSignupActivity oldSignupActivity = (OldSignupActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B6 = N6.b(oldSignupActivity.getApplicationContext());
                if (componentCallbacks2B6 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B6 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B6).u()) && !oldSignupActivity.q) {
                        oldSignupActivity.q = true;
                        C4622e c4622e6 = (C4622e) ((p) oldSignupActivity.d());
                        oldSignupActivity.c = c4622e6.a();
                        u uVar5 = c4622e6.b;
                        oldSignupActivity.e = uVar5.Q0();
                        oldSignupActivity.l = new C4636c((com.quizlet.quizletandroid.util.g) uVar5.B1.get());
                        uVar5.h1();
                        break;
                    }
                }
                break;
            case 8:
                ServerDrivenOnboardingActivity serverDrivenOnboardingActivity = (ServerDrivenOnboardingActivity) abstractActivityC0055k;
                if (!serverDrivenOnboardingActivity.g) {
                    serverDrivenOnboardingActivity.g = true;
                    serverDrivenOnboardingActivity.c = ((C4622e) ((com.quizlet.quizletandroid.ui.onboarding.ui.c) serverDrivenOnboardingActivity.d())).b.Q0();
                    break;
                }
                break;
            case 9:
                SetPreviewActivity setPreviewActivity = (SetPreviewActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B7 = N6.b(setPreviewActivity.getApplicationContext());
                if (componentCallbacks2B7 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B7 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B7).u()) && !setPreviewActivity.p) {
                        setPreviewActivity.p = true;
                        C4622e c4622e7 = (C4622e) ((com.quizlet.quizletandroid.ui.preview.d) setPreviewActivity.d());
                        setPreviewActivity.c = c4622e7.a();
                        u uVar6 = c4622e7.b;
                        setPreviewActivity.e = uVar6.Q0();
                        setPreviewActivity.q = (com.quizlet.qutils.image.loading.a) uVar6.s.get();
                        break;
                    }
                }
                break;
            case 10:
                ProfileActivity profileActivity = (ProfileActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B8 = N6.b(profileActivity.getApplicationContext());
                if (componentCallbacks2B8 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B8 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B8).u()) && !profileActivity.o) {
                        profileActivity.o = true;
                        C4622e c4622e8 = (C4622e) ((com.quizlet.quizletandroid.ui.profile.c) profileActivity.d());
                        profileActivity.c = c4622e8.a();
                        profileActivity.e = c4622e8.b.Q0();
                        break;
                    }
                }
                break;
            case 11:
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B9 = N6.b(qLiveQrCodeReaderActivity.getApplicationContext());
                if (componentCallbacks2B9 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B9 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B9).u()) && !qLiveQrCodeReaderActivity.p) {
                        qLiveQrCodeReaderActivity.p = true;
                        C4622e c4622e9 = (C4622e) ((com.quizlet.quizletandroid.ui.qrcodes.c) qLiveQrCodeReaderActivity.d());
                        qLiveQrCodeReaderActivity.c = c4622e9.a();
                        u uVar7 = c4622e9.b;
                        qLiveQrCodeReaderActivity.e = uVar7.Q0();
                        com.quizlet.infra.legacysyncengine.managers.g livePreferencesManager = new com.quizlet.infra.legacysyncengine.managers.g(uVar7.q());
                        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar7.Z.get();
                        com.quizlet.features.emailconfirmation.logging.a quizetLiveLogger = uVar7.p0();
                        com.google.mlkit.vision.barcode.b bVar = com.quizlet.quizletandroid.ui.qrcodes.di.a.a;
                        com.google.android.gms.common.internal.u.i(bVar, "You must provide a valid BarcodeScannerOptions.");
                        com.google.mlkit.vision.barcode.internal.b bVar2 = (com.google.mlkit.vision.barcode.internal.b) com.google.mlkit.common.sdkinternal.f.c().a(com.google.mlkit.vision.barcode.internal.b.class);
                        bVar2.getClass();
                        com.google.mlkit.vision.barcode.internal.c barcodeScanner = new com.google.mlkit.vision.barcode.internal.c(bVar, (com.google.mlkit.vision.barcode.internal.e) bVar2.a.p(bVar), (Executor) bVar2.b.a.get(), M7.d(true != com.google.mlkit.vision.barcode.internal.a.c() ? "play-services-mlkit-barcode-scanning" : "barcode-scanning"));
                        Intrinsics.checkNotNullExpressionValue(barcodeScanner, "getClient(...)");
                        Context applicationContext = uVar7.q();
                        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
                        Object systemService = applicationContext.getSystemService("camera");
                        Intrinsics.e(systemService, "null cannot be cast to non-null type android.hardware.camera2.CameraManager");
                        CameraManager cameraManager = (CameraManager) systemService;
                        Intrinsics.checkNotNullParameter(livePreferencesManager, "livePreferencesManager");
                        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
                        Intrinsics.checkNotNullParameter(quizetLiveLogger, "quizetLiveLogger");
                        Intrinsics.checkNotNullParameter(barcodeScanner, "barcodeScanner");
                        Intrinsics.checkNotNullParameter(cameraManager, "cameraManager");
                        com.google.android.datatransport.cct.internal.s sVar2 = new com.google.android.datatransport.cct.internal.s();
                        sVar2.b = livePreferencesManager;
                        sVar2.c = loggedInUserManager;
                        sVar2.d = quizetLiveLogger;
                        sVar2.e = barcodeScanner;
                        sVar2.f = cameraManager;
                        sVar2.g = new Handler();
                        sVar2.a = new String[]{"android.permission.CAMERA"};
                        qLiveQrCodeReaderActivity.r = sVar2;
                        GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
                        Intrinsics.checkNotNullExpressionValue(googleApiAvailability, "getInstance(...)");
                        S6.c(googleApiAvailability);
                        qLiveQrCodeReaderActivity.s = googleApiAvailability;
                        break;
                    }
                }
                break;
            case 12:
                SearchActivity searchActivity = (SearchActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B10 = N6.b(searchActivity.getApplicationContext());
                if (componentCallbacks2B10 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B10 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B10).u()) && !searchActivity.p) {
                        searchActivity.p = true;
                        C4622e c4622e10 = (C4622e) ((com.quizlet.quizletandroid.ui.search.a) searchActivity.d());
                        searchActivity.c = c4622e10.a();
                        searchActivity.e = c4622e10.b.Q0();
                        break;
                    }
                }
                break;
            case 13:
                EditSetActivity editSetActivity = (EditSetActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B11 = N6.b(editSetActivity.getApplicationContext());
                int i = EditSetActivity.M;
                if (componentCallbacks2B11 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B11 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B11).u()) && !editSetActivity.L) {
                        editSetActivity.L = true;
                        C4622e c4622e11 = (C4622e) ((com.quizlet.quizletandroid.ui.setcreation.activities.e) editSetActivity.d());
                        editSetActivity.c = c4622e11.a();
                        u uVar8 = c4622e11.b;
                        editSetActivity.e = uVar8.Q0();
                        editSetActivity.n = uVar8.Z();
                        editSetActivity.o = uVar8.l0();
                        editSetActivity.p = (DatabaseHelper) uVar8.v.get();
                        editSetActivity.q = (com.quizlet.quizletandroid.util.f) uVar8.a0.get();
                        editSetActivity.r = (com.quizlet.infra.legacysyncengine.net.f) uVar8.U.get();
                        editSetActivity.s = (v) uVar8.E1.get();
                        editSetActivity.t = (com.quizlet.infra.legacysyncengine.managers.d) uVar8.Z.get();
                        editSetActivity.u = (IQuizletApiClient) uVar8.O.get();
                        editSetActivity.v = (EventLogger) uVar8.l0.get();
                        editSetActivity.w = com.quizlet.featuregate.injection.a.l();
                        editSetActivity.x = com.quizlet.featuregate.injection.a.j();
                        editSetActivity.y = uVar8.x();
                        editSetActivity.z = (com.quizlet.offline.managers.b) uVar8.d1.get();
                        break;
                    }
                }
                break;
            case 14:
                EditSetDetailsActivity editSetDetailsActivity = (EditSetDetailsActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B12 = N6.b(editSetDetailsActivity.getApplicationContext());
                int i2 = EditSetDetailsActivity.y;
                if (componentCallbacks2B12 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B12 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B12).u()) && !editSetDetailsActivity.x) {
                        editSetDetailsActivity.x = true;
                        C4622e c4622e12 = (C4622e) ((com.quizlet.quizletandroid.ui.setcreation.activities.i) editSetDetailsActivity.d());
                        editSetDetailsActivity.c = c4622e12.a();
                        u uVar9 = c4622e12.b;
                        editSetDetailsActivity.e = uVar9.Q0();
                        uVar9.Z();
                        SharedPreferences sharedPreferences = uVar9.A0();
                        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                        uVar9.l0();
                        editSetDetailsActivity.m = (DatabaseHelper) uVar9.v.get();
                        editSetDetailsActivity.n = (com.quizlet.quizletandroid.util.f) uVar9.a0.get();
                        editSetDetailsActivity.o = (com.quizlet.infra.legacysyncengine.managers.i) uVar9.S.get();
                        uVar9.k1();
                        editSetDetailsActivity.p = uVar9.x();
                        editSetDetailsActivity.q = uVar9.m0();
                        break;
                    }
                }
                break;
            case 15:
                EditSetLanguageSelectionActivity editSetLanguageSelectionActivity = (EditSetLanguageSelectionActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B13 = N6.b(editSetLanguageSelectionActivity.getApplicationContext());
                int i3 = EditSetLanguageSelectionActivity.z;
                if (componentCallbacks2B13 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B13 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B13).u()) && !editSetLanguageSelectionActivity.y) {
                        editSetLanguageSelectionActivity.y = true;
                        C4622e c4622e13 = (C4622e) ((com.quizlet.quizletandroid.ui.setcreation.activities.j) editSetLanguageSelectionActivity.d());
                        editSetLanguageSelectionActivity.c = c4622e13.a();
                        u uVar10 = c4622e13.b;
                        editSetLanguageSelectionActivity.e = uVar10.Q0();
                        editSetLanguageSelectionActivity.m = (com.quizlet.quizletandroid.util.f) uVar10.a0.get();
                        editSetLanguageSelectionActivity.n = (com.quizlet.infra.legacysyncengine.managers.d) uVar10.Z.get();
                        editSetLanguageSelectionActivity.o = new com.quizlet.quizletandroid.ui.setcreation.adapters.a(0);
                        break;
                    }
                }
                break;
            case 16:
                EditSetPermissionSelectionActivity editSetPermissionSelectionActivity = (EditSetPermissionSelectionActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B14 = N6.b(editSetPermissionSelectionActivity.getApplicationContext());
                if (componentCallbacks2B14 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B14 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B14).u()) && !editSetPermissionSelectionActivity.p) {
                        editSetPermissionSelectionActivity.p = true;
                        C4622e c4622e14 = (C4622e) ((k) editSetPermissionSelectionActivity.d());
                        editSetPermissionSelectionActivity.c = c4622e14.a();
                        u uVar11 = c4622e14.b;
                        editSetPermissionSelectionActivity.e = uVar11.Q0();
                        uVar11.Z();
                        uVar11.l0();
                        editSetPermissionSelectionActivity.t = uVar11.m0();
                        editSetPermissionSelectionActivity.u = new com.quizlet.shared.usecase.folderstudymaterials.d(25);
                        break;
                    }
                }
                break;
            case 17:
                EditTermImagePreviewActivity editTermImagePreviewActivity = (EditTermImagePreviewActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B15 = N6.b(editTermImagePreviewActivity.getApplicationContext());
                int i4 = EditTermImagePreviewActivity.t;
                if (componentCallbacks2B15 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B15 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B15).u()) && !editTermImagePreviewActivity.s) {
                        editTermImagePreviewActivity.s = true;
                        C4622e c4622e15 = (C4622e) ((com.quizlet.quizletandroid.ui.setcreation.activities.l) editTermImagePreviewActivity.d());
                        editTermImagePreviewActivity.c = c4622e15.a();
                        u uVar12 = c4622e15.b;
                        editTermImagePreviewActivity.e = uVar12.Q0();
                        editTermImagePreviewActivity.l = (com.quizlet.qutils.image.loading.a) uVar12.s.get();
                        uVar12.Z();
                        editTermImagePreviewActivity.o = uVar12.l0();
                        break;
                    }
                }
                break;
            case 18:
                InputPasswordActivity inputPasswordActivity = (InputPasswordActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B16 = N6.b(inputPasswordActivity.getApplicationContext());
                if (componentCallbacks2B16 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B16 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B16).u()) && !inputPasswordActivity.p) {
                        inputPasswordActivity.p = true;
                        C4622e c4622e16 = (C4622e) ((m) inputPasswordActivity.d());
                        inputPasswordActivity.c = c4622e16.a();
                        u uVar13 = c4622e16.b;
                        inputPasswordActivity.e = uVar13.Q0();
                        inputPasswordActivity.q = uVar13.l0();
                        break;
                    }
                }
                break;
            case 19:
                ScanDocumentActivity scanDocumentActivity = (ScanDocumentActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B17 = N6.b(scanDocumentActivity.getApplicationContext());
                if (componentCallbacks2B17 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B17 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B17).u()) && !scanDocumentActivity.n) {
                        scanDocumentActivity.n = true;
                        C4622e c4622e17 = (C4622e) ((q) scanDocumentActivity.d());
                        scanDocumentActivity.c = c4622e17.a();
                        scanDocumentActivity.e = c4622e17.b.Q0();
                        break;
                    }
                }
                break;
            case 20:
                AddSetToClassActivity addSetToClassActivity = (AddSetToClassActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B18 = N6.b(addSetToClassActivity.getApplicationContext());
                if (componentCallbacks2B18 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B18 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B18).u()) && !addSetToClassActivity.o) {
                        addSetToClassActivity.o = true;
                        C4622e c4622e18 = (C4622e) ((com.quizlet.quizletandroid.ui.setpage.addset.b) addSetToClassActivity.d());
                        addSetToClassActivity.c = c4622e18.a();
                        u uVar14 = c4622e18.b;
                        addSetToClassActivity.e = uVar14.Q0();
                        addSetToClassActivity.p = uVar14.l0();
                        break;
                    }
                }
                break;
            case 21:
                ShareSheetReceiverActivity shareSheetReceiverActivity = (ShareSheetReceiverActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B19 = N6.b(shareSheetReceiverActivity.getApplicationContext());
                if (componentCallbacks2B19 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B19 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B19).u()) && !shareSheetReceiverActivity.f) {
                        shareSheetReceiverActivity.f = true;
                        shareSheetReceiverActivity.g = ((C4622e) ((com.quizlet.quizletandroid.ui.sharereceiver.a) shareSheetReceiverActivity.d())).b.E();
                        break;
                    }
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                CreateSetShortcutInterstitialActivity createSetShortcutInterstitialActivity = (CreateSetShortcutInterstitialActivity) abstractActivityC0055k;
                if (!createSetShortcutInterstitialActivity.f) {
                    createSetShortcutInterstitialActivity.f = true;
                    createSetShortcutInterstitialActivity.g = (com.quizlet.infra.legacysyncengine.managers.d) ((C4622e) ((com.quizlet.quizletandroid.ui.shortcuts.b) createSetShortcutInterstitialActivity.d())).b.Z.get();
                    break;
                }
                break;
            case EventType.AUDIO /* 23 */:
                LearningAssistantActivity learningAssistantActivity = (LearningAssistantActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B20 = N6.b(learningAssistantActivity.getApplicationContext());
                if (componentCallbacks2B20 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B20 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B20).u()) && !learningAssistantActivity.p) {
                        learningAssistantActivity.p = true;
                        C4622e c4622e19 = (C4622e) ((n) learningAssistantActivity.d());
                        learningAssistantActivity.c = c4622e19.a();
                        learningAssistantActivity.e = c4622e19.b.Q0();
                        learningAssistantActivity.u = c4622e19.e();
                        break;
                    }
                }
                break;
            case EventType.VIDEO /* 24 */:
                LearnSettingsActivity learnSettingsActivity = (LearnSettingsActivity) abstractActivityC0055k;
                if (!learnSettingsActivity.h) {
                    learnSettingsActivity.h = true;
                    learnSettingsActivity.c = ((C4622e) ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.j) learnSettingsActivity.d())).b.Q0();
                    break;
                }
                break;
            case EventType.SUBS /* 25 */:
                MatchActivity matchActivity = (MatchActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B21 = N6.b(matchActivity.getApplicationContext());
                if (componentCallbacks2B21 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B21 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B21).u()) && !matchActivity.p) {
                        matchActivity.p = true;
                        C4622e c4622e20 = (C4622e) ((com.quizlet.quizletandroid.ui.studymodes.match.activity.c) matchActivity.d());
                        matchActivity.c = c4622e20.a();
                        matchActivity.e = c4622e20.b.Q0();
                        break;
                    }
                }
                break;
            case EventType.CDN /* 26 */:
                MatchSettingsActivity matchSettingsActivity = (MatchSettingsActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B22 = N6.b(matchSettingsActivity.getApplicationContext());
                if (componentCallbacks2B22 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B22 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B22).u()) && !matchSettingsActivity.p) {
                        matchSettingsActivity.p = true;
                        C4622e c4622e21 = (C4622e) ((com.quizlet.quizletandroid.ui.studymodes.match.settings.a) matchSettingsActivity.d());
                        matchSettingsActivity.c = c4622e21.a();
                        matchSettingsActivity.e = c4622e21.b.Q0();
                        break;
                    }
                }
                break;
            case 27:
                TestStudyModeActivity testStudyModeActivity = (TestStudyModeActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B23 = N6.b(testStudyModeActivity.getApplicationContext());
                if (componentCallbacks2B23 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B23 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B23).u()) && !testStudyModeActivity.p) {
                        testStudyModeActivity.p = true;
                        C4622e c4622e22 = (C4622e) ((com.quizlet.quizletandroid.ui.studymodes.testmode.activities.g) testStudyModeActivity.d());
                        testStudyModeActivity.c = c4622e22.a();
                        testStudyModeActivity.e = c4622e22.b.Q0();
                        testStudyModeActivity.q = c4622e22.e();
                        break;
                    }
                }
                break;
            case 28:
                WriteModeActivity writeModeActivity = (WriteModeActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B24 = N6.b(writeModeActivity.getApplicationContext());
                int i5 = WriteModeActivity.z1;
                if (componentCallbacks2B24 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B24 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B24).u()) && !writeModeActivity.y1) {
                        writeModeActivity.y1 = true;
                        C4622e c4622e23 = (C4622e) ((com.quizlet.quizletandroid.ui.studymodes.write.d) writeModeActivity.d());
                        writeModeActivity.c = c4622e23.a();
                        u uVar15 = c4622e23.b;
                        writeModeActivity.e = uVar15.Q0();
                        uVar15.j1();
                        uVar15.Z();
                        writeModeActivity.x = uVar15.l0();
                        writeModeActivity.y = uVar15.d1();
                        writeModeActivity.z = uVar15.B0();
                        writeModeActivity.A = (EventLogger) uVar15.l0.get();
                        writeModeActivity.B = (SearchEventLogger) uVar15.G1.get();
                        writeModeActivity.C = uVar15.F0();
                        uVar15.m0();
                        writeModeActivity.D = (com.quizlet.offline.managers.b) uVar15.d1.get();
                        writeModeActivity.E = (com.quizlet.infra.legacysyncengine.net.f) uVar15.U.get();
                        writeModeActivity.F = (com.quizlet.infra.legacysyncengine.net.c) uVar15.Q.get();
                        writeModeActivity.G = (com.quizlet.infra.legacysyncengine.managers.d) uVar15.Z.get();
                        writeModeActivity.H = uVar15.O();
                        C4624g c4624g = c4622e23.c;
                        writeModeActivity.I = (StudySessionQuestionEventLogger) c4624g.h.get();
                        writeModeActivity.i1 = (com.quizlet.quizletandroid.managers.audio.h) uVar15.f0.get();
                        writeModeActivity.j1 = (com.quizlet.infra.legacysyncengine.net.f) uVar15.U.get();
                        writeModeActivity.k1 = (com.quizlet.infra.legacysyncengine.net.c) uVar15.Q.get();
                        writeModeActivity.l1 = (com.quizlet.infra.legacysyncengine.managers.i) uVar15.S.get();
                        writeModeActivity.m1 = (com.quizlet.qutils.image.loading.a) uVar15.s.get();
                        writeModeActivity.n1 = (C4595c) c4622e23.W.get();
                        writeModeActivity.o1 = new com.features.flashcards.creatormarketing.h((EventLogger) uVar15.l0.get(), 3);
                        writeModeActivity.p1 = (com.quizlet.features.infra.basestudy.manager.d) uVar15.D1.get();
                        writeModeActivity.q1 = new com.quizlet.data.repository.widget.b(new com.quizlet.data.interactor.course.a((Braze) c4624g.b.W0.get()), uVar15.l0());
                        grading.core.a[] aVarArr = grading.factories.a.a;
                        writeModeActivity.r1 = grading.factories.a.a();
                        writeModeActivity.s1 = (ExecutionRouter) uVar15.w.get();
                        break;
                    }
                }
                break;
            default:
                WriteSettingsActivity writeSettingsActivity = (WriteSettingsActivity) abstractActivityC0055k;
                ComponentCallbacks2 componentCallbacks2B25 = N6.b(writeSettingsActivity.getApplicationContext());
                int i6 = WriteSettingsActivity.u;
                if (componentCallbacks2B25 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B25 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B25).u()) && !writeSettingsActivity.t) {
                        writeSettingsActivity.t = true;
                        C4622e c4622e24 = (C4622e) ((com.quizlet.quizletandroid.ui.studymodes.write.m) writeSettingsActivity.d());
                        writeSettingsActivity.c = c4622e24.a();
                        writeSettingsActivity.e = c4622e24.b.Q0();
                        break;
                    }
                }
                break;
        }
    }
}
