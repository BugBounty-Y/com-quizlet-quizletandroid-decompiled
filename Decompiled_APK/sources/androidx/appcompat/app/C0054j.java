package androidx.appcompat.app;

import android.content.ComponentCallbacks2;
import androidx.camera.camera2.internal.c0;
import androidx.datastore.core.InterfaceC1076h;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.quizlet.ads.ui.activity.AdsActivity;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.pushnotifications.PushNotificationLogger;
import com.quizlet.explanations.questiondetail.ui.QuestionDetailActivity;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.features.achievements.ui.AchievementsActivity;
import com.quizlet.features.blocks.GamesActivity;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity;
import com.quizlet.features.flashcards.FlashcardsActivity;
import com.quizlet.features.flashcards.InterfaceC4231e;
import com.quizlet.features.folders.FolderActivity;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import com.quizlet.features.notes.paywall.ScanNotesPaywallActivity;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import com.quizlet.features.onboarding.flashcards.OnboardingFlashcardsActivity;
import com.quizlet.features.onboarding.navigation.OnboardingNavigationActivity;
import com.quizlet.features.onboarding.survey.OnboardingSurveyActivity;
import com.quizlet.features.paywall.PaywallActivity;
import com.quizlet.features.practicetest.PracticeTestActivity;
import com.quizlet.features.questionnaire.navigation.QuestionnaireNavigationActivity;
import com.quizlet.features.setpage.NewSetPageActivity;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.features.settings.SettingsActivity;
import com.quizlet.features.universaluploadflow.UniversalUploadFlowActivity;
import com.quizlet.features.userprofile.ui.UserProfileActivity;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.ui.RootActivity;
import com.quizlet.quizletandroid.ui.classcreation.ClassCreationActivity;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.app.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0054j implements androidx.activity.contextaware.b {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.activity.s b;

    public /* synthetic */ C0054j(androidx.activity.s sVar, int i) {
        this.a = i;
        this.b = sVar;
    }

    @Override // androidx.activity.contextaware.b
    public final void a(androidx.activity.s sVar) {
        switch (this.a) {
            case 0:
                AbstractActivityC0055k abstractActivityC0055k = (AbstractActivityC0055k) this.b;
                AbstractC0061q abstractC0061qQ = abstractActivityC0055k.q();
                abstractC0061qQ.a();
                abstractActivityC0055k.getSavedStateRegistry().a("androidx:appcompat");
                abstractC0061qQ.d();
                break;
            case 1:
                AdsActivity adsActivity = (AdsActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B = N6.b(adsActivity.getApplicationContext());
                if (componentCallbacks2B instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u()) && !adsActivity.p) {
                        adsActivity.p = true;
                        C4622e c4622e = (C4622e) ((com.quizlet.ads.ui.activity.c) adsActivity.d());
                        adsActivity.c = c4622e.a();
                        com.quizlet.quizletandroid.u uVar = c4622e.b;
                        adsActivity.e = uVar.Q0();
                        adsActivity.q = new com.quizlet.quizletandroid.managers.upgrade.a(0);
                        adsActivity.r = (com.quizlet.ads.g) uVar.v1.get();
                        break;
                    }
                }
                break;
            case 2:
                QuestionDetailActivity questionDetailActivity = (QuestionDetailActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B2 = N6.b(questionDetailActivity.getApplicationContext());
                if (componentCallbacks2B2 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B2 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B2).u()) && !questionDetailActivity.p) {
                        questionDetailActivity.p = true;
                        C4622e c4622e2 = (C4622e) ((com.quizlet.explanations.questiondetail.ui.b) questionDetailActivity.d());
                        questionDetailActivity.c = c4622e2.a();
                        questionDetailActivity.e = c4622e2.b.Q0();
                        questionDetailActivity.q = new com.quizlet.shared.usecase.srs.a(24);
                        break;
                    }
                }
                break;
            case 3:
                TextbookActivity textbookActivity = (TextbookActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B3 = N6.b(textbookActivity.getApplicationContext());
                if (componentCallbacks2B3 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B3 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B3).u()) && !textbookActivity.p) {
                        textbookActivity.p = true;
                        C4622e c4622e3 = (C4622e) ((com.quizlet.explanations.textbook.ui.a) textbookActivity.d());
                        textbookActivity.c = c4622e3.a();
                        textbookActivity.e = c4622e3.b.Q0();
                        textbookActivity.q = new com.onetrust.otpublishers.headless.Internal.Helper.h(25);
                        break;
                    }
                }
                break;
            case 4:
                AchievementsActivity achievementsActivity = (AchievementsActivity) this.b;
                if (!achievementsActivity.h) {
                    achievementsActivity.h = true;
                    achievementsActivity.c = ((C4622e) ((com.quizlet.features.achievements.ui.b) achievementsActivity.d())).b.Q0();
                    break;
                }
                break;
            case 5:
                GamesActivity gamesActivity = (GamesActivity) this.b;
                if (!gamesActivity.h) {
                    gamesActivity.h = true;
                    com.quizlet.quizletandroid.u uVar2 = ((C4622e) ((com.quizlet.features.blocks.e) gamesActivity.d())).b;
                    gamesActivity.c = uVar2.Q0();
                    gamesActivity.i = (com.quizlet.features.consent.onetrust.d) uVar2.R0.get();
                    break;
                }
                break;
            case 6:
                EmailConfirmationActivity emailConfirmationActivity = (EmailConfirmationActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B4 = N6.b(emailConfirmationActivity.getApplicationContext());
                if (componentCallbacks2B4 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B4 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B4).u()) && !emailConfirmationActivity.o) {
                        emailConfirmationActivity.o = true;
                        C4622e c4622e4 = (C4622e) ((com.quizlet.features.emailconfirmation.ui.activities.k) emailConfirmationActivity.d());
                        emailConfirmationActivity.c = c4622e4.a();
                        emailConfirmationActivity.e = c4622e4.b.Q0();
                        emailConfirmationActivity.p = (com.quizlet.quizletandroid.ui.navigationmanagers.a) c4622e4.j.get();
                        break;
                    }
                }
                break;
            case 7:
                MagicLinkConfirmationActivity magicLinkConfirmationActivity = (MagicLinkConfirmationActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B5 = N6.b(magicLinkConfirmationActivity.getApplicationContext());
                if (componentCallbacks2B5 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B5 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B5).u()) && !magicLinkConfirmationActivity.o) {
                        magicLinkConfirmationActivity.o = true;
                        C4622e c4622e5 = (C4622e) ((com.quizlet.features.emailconfirmation.ui.activities.r) magicLinkConfirmationActivity.d());
                        magicLinkConfirmationActivity.c = c4622e5.a();
                        magicLinkConfirmationActivity.e = c4622e5.b.Q0();
                        magicLinkConfirmationActivity.p = (com.quizlet.quizletandroid.ui.navigationmanagers.a) c4622e5.j.get();
                        break;
                    }
                }
                break;
            case 8:
                FlashcardsActivity flashcardsActivity = (FlashcardsActivity) this.b;
                if (!flashcardsActivity.h) {
                    flashcardsActivity.h = true;
                    flashcardsActivity.c = ((C4622e) ((InterfaceC4231e) flashcardsActivity.d())).b.Q0();
                    break;
                }
                break;
            case 9:
                FolderActivity folderActivity = (FolderActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B6 = N6.b(folderActivity.getApplicationContext());
                if (componentCallbacks2B6 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B6 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B6).u()) && !folderActivity.h) {
                        folderActivity.h = true;
                        com.quizlet.quizletandroid.u uVar3 = ((C4622e) ((com.quizlet.features.folders.b) folderActivity.d())).b;
                        folderActivity.c = uVar3.Q0();
                        folderActivity.i = (com.quizlet.quizletandroid.managers.c) uVar3.i1.get();
                        break;
                    }
                }
                break;
            case 10:
                MagicNotesDetailActivity magicNotesDetailActivity = (MagicNotesDetailActivity) this.b;
                if (!magicNotesDetailActivity.g) {
                    magicNotesDetailActivity.g = true;
                    com.quizlet.quizletandroid.u uVar4 = ((C4622e) ((com.quizlet.features.notes.detail.b) magicNotesDetailActivity.d())).b;
                    magicNotesDetailActivity.c = uVar4.Q0();
                    magicNotesDetailActivity.h = new com.quizlet.quizletandroid.ui.navigationmanagers.e(uVar4.q());
                    break;
                }
                break;
            case 11:
                ScanNotesPaywallActivity scanNotesPaywallActivity = (ScanNotesPaywallActivity) this.b;
                if (!scanNotesPaywallActivity.g) {
                    scanNotesPaywallActivity.g = true;
                    com.quizlet.quizletandroid.u uVar5 = ((C4622e) ((com.quizlet.features.notes.paywall.d) scanNotesPaywallActivity.d())).b;
                    scanNotesPaywallActivity.c = uVar5.Q0();
                    scanNotesPaywallActivity.j = new com.quizlet.quizletandroid.ui.navigationmanagers.f(uVar5.q());
                    break;
                }
                break;
            case 12:
                UploadNotesActivity uploadNotesActivity = (UploadNotesActivity) this.b;
                if (!uploadNotesActivity.g) {
                    uploadNotesActivity.g = true;
                    com.quizlet.quizletandroid.u uVar6 = ((C4622e) ((com.quizlet.features.notes.upload.b) uploadNotesActivity.d())).b;
                    uploadNotesActivity.c = uVar6.Q0();
                    uploadNotesActivity.h = new com.quizlet.quizletandroid.ui.navigationmanagers.e(uVar6.q());
                    break;
                }
                break;
            case 13:
                OnboardingFlashcardsActivity onboardingFlashcardsActivity = (OnboardingFlashcardsActivity) this.b;
                if (!onboardingFlashcardsActivity.g) {
                    onboardingFlashcardsActivity.g = true;
                    onboardingFlashcardsActivity.c = ((C4622e) ((com.quizlet.features.onboarding.flashcards.h) onboardingFlashcardsActivity.d())).b.Q0();
                    break;
                }
                break;
            case 14:
                OnboardingNavigationActivity onboardingNavigationActivity = (OnboardingNavigationActivity) this.b;
                if (!onboardingNavigationActivity.d) {
                    onboardingNavigationActivity.d = true;
                    onboardingNavigationActivity.i = (com.quizlet.features.infra.navigation.A) ((C4622e) ((com.quizlet.features.onboarding.navigation.f) onboardingNavigationActivity.d())).v.get();
                    break;
                }
                break;
            case 15:
                OnboardingSurveyActivity onboardingSurveyActivity = (OnboardingSurveyActivity) this.b;
                if (!onboardingSurveyActivity.g) {
                    onboardingSurveyActivity.g = true;
                    onboardingSurveyActivity.c = ((C4622e) ((com.quizlet.features.onboarding.survey.h) onboardingSurveyActivity.d())).b.Q0();
                    break;
                }
                break;
            case 16:
                PaywallActivity paywallActivity = (PaywallActivity) this.b;
                if (!paywallActivity.g) {
                    paywallActivity.g = true;
                    C4622e c4622e6 = (C4622e) ((com.quizlet.features.paywall.c) paywallActivity.d());
                    paywallActivity.c = c4622e6.b.Q0();
                    paywallActivity.i = (com.quizlet.features.infra.navigation.A) c4622e6.v.get();
                    break;
                }
                break;
            case 17:
                PracticeTestActivity practiceTestActivity = (PracticeTestActivity) this.b;
                if (!practiceTestActivity.g) {
                    practiceTestActivity.g = true;
                    practiceTestActivity.c = ((C4622e) ((com.quizlet.features.practicetest.c) practiceTestActivity.d())).b.Q0();
                    break;
                }
                break;
            case 18:
                QuestionnaireNavigationActivity questionnaireNavigationActivity = (QuestionnaireNavigationActivity) this.b;
                if (!questionnaireNavigationActivity.g) {
                    questionnaireNavigationActivity.g = true;
                    C4622e c4622e7 = (C4622e) ((com.quizlet.features.questionnaire.navigation.e) questionnaireNavigationActivity.d());
                    questionnaireNavigationActivity.c = c4622e7.b.Q0();
                    questionnaireNavigationActivity.i = new com.quizlet.features.questionnaire.steps.h();
                    com.quizlet.usecase.b questionnaireShimUseCaseMutator = (com.quizlet.usecase.b) c4622e7.c.e.get();
                    Intrinsics.checkNotNullParameter(questionnaireShimUseCaseMutator, "questionnaireShimUseCaseMutator");
                    questionnaireNavigationActivity.j = new com.quizlet.data.interactor.course.a(questionnaireShimUseCaseMutator);
                    break;
                }
                break;
            case 19:
                NewSetPageActivity newSetPageActivity = (NewSetPageActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B7 = N6.b(newSetPageActivity.getApplicationContext());
                if (componentCallbacks2B7 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B7 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B7).u()) && !newSetPageActivity.h) {
                        newSetPageActivity.h = true;
                        newSetPageActivity.c = ((C4622e) ((com.quizlet.features.setpage.c) newSetPageActivity.d())).b.Q0();
                        break;
                    }
                }
                break;
            case 20:
                SetPageActivity setPageActivity = (SetPageActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B8 = N6.b(setPageActivity.getApplicationContext());
                if (componentCallbacks2B8 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B8 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B8).u()) && !setPageActivity.g1) {
                        setPageActivity.g1 = true;
                        C4622e c4622e8 = (C4622e) ((com.quizlet.features.setpage.s) setPageActivity.d());
                        setPageActivity.c = c4622e8.a();
                        com.quizlet.quizletandroid.u uVar7 = c4622e8.b;
                        setPageActivity.e = uVar7.Q0();
                        setPageActivity.w = (com.quizlet.quizletandroid.managers.c) uVar7.i1.get();
                        setPageActivity.x = (com.quizlet.features.setpage.utils.setpermissions.a) uVar7.h1.get();
                        setPageActivity.y = (com.quizlet.quizletandroid.util.a) uVar7.y1.get();
                        setPageActivity.z = uVar7.O();
                        setPageActivity.A = (com.google.firebase.crashlytics.b) uVar7.t.get();
                        setPageActivity.B = new com.quizlet.shared.usecase.folderstudymaterials.b(27);
                        setPageActivity.C = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(uVar7.z());
                        com.quizlet.quizletandroid.ui.webpages.a webPageHelper = com.quizlet.quizletandroid.ui.webpages.a.a;
                        Intrinsics.checkNotNullParameter(webPageHelper, "webPageHelper");
                        com.quizlet.quizletandroid.ui.common.adapter.c reportContent = new com.quizlet.quizletandroid.ui.common.adapter.c();
                        Intrinsics.checkNotNullParameter(reportContent, "reportContent");
                        setPageActivity.D = new com.quizlet.quizletandroid.ui.setpage.navigation.a();
                        com.quizlet.quizletandroid.t adaptiveBannerAdViewHelperProvider = uVar7.z1;
                        com.quizlet.quizletandroid.t prebidAdaptiveBannerAdViewHelperProvider = uVar7.A1;
                        com.quizlet.data.repository.user.a enablePrebidSdkFeature = uVar7.y();
                        Intrinsics.checkNotNullParameter(adaptiveBannerAdViewHelperProvider, "adaptiveBannerAdViewHelperProvider");
                        Intrinsics.checkNotNullParameter(prebidAdaptiveBannerAdViewHelperProvider, "prebidAdaptiveBannerAdViewHelperProvider");
                        Intrinsics.checkNotNullParameter(enablePrebidSdkFeature, "enablePrebidSdkFeature");
                        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c();
                        cVar.a = adaptiveBannerAdViewHelperProvider;
                        cVar.b = prebidAdaptiveBannerAdViewHelperProvider;
                        cVar.c = enablePrebidSdkFeature;
                        setPageActivity.E = cVar;
                        setPageActivity.F = new com.quizlet.quizletandroid.ui.debug.a();
                        break;
                    }
                }
                break;
            case 21:
                SettingsActivity settingsActivity = (SettingsActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B9 = N6.b(settingsActivity.getApplicationContext());
                if (componentCallbacks2B9 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B9 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B9).u()) && !settingsActivity.n) {
                        settingsActivity.n = true;
                        C4622e c4622e9 = (C4622e) ((com.quizlet.features.settings.a) settingsActivity.d());
                        settingsActivity.c = c4622e9.a();
                        settingsActivity.e = c4622e9.b.Q0();
                        settingsActivity.o = new com.quizlet.quizletandroid.ui.debug.a();
                        break;
                    }
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                UniversalUploadFlowActivity universalUploadFlowActivity = (UniversalUploadFlowActivity) this.b;
                if (!universalUploadFlowActivity.g) {
                    universalUploadFlowActivity.g = true;
                    universalUploadFlowActivity.c = ((C4622e) ((com.quizlet.features.universaluploadflow.b) universalUploadFlowActivity.d())).b.Q0();
                    break;
                }
                break;
            case EventType.AUDIO /* 23 */:
                UserProfileActivity userProfileActivity = (UserProfileActivity) this.b;
                if (!userProfileActivity.h) {
                    userProfileActivity.h = true;
                    C4622e c4622e10 = (C4622e) ((com.quizlet.features.userprofile.ui.b) userProfileActivity.d());
                    userProfileActivity.c = c4622e10.b.Q0();
                    userProfileActivity.i = c4622e10.d();
                    break;
                }
                break;
            case EventType.VIDEO /* 24 */:
                LoginNavActivity loginNavActivity = (LoginNavActivity) this.b;
                if (!loginNavActivity.h) {
                    loginNavActivity.h = true;
                    loginNavActivity.c = ((C4622e) ((com.quizlet.login.b) loginNavActivity.d())).b.Q0();
                    break;
                }
                break;
            case EventType.SUBS /* 25 */:
                RootActivity rootActivity = (RootActivity) this.b;
                if (!rootActivity.f) {
                    rootActivity.f = true;
                    com.quizlet.quizletandroid.u uVar8 = ((C4622e) ((com.quizlet.quizletandroid.ui.d) rootActivity.d())).b;
                    rootActivity.g = new c0((com.quizlet.infra.legacysyncengine.managers.d) uVar8.Z.get(), (EventLogger) uVar8.l0.get(), new com.quizlet.analytics.marketing.appsflyer.b(uVar8.q(), uVar8.P0()), new com.lyft.android.scissors.b(new C4567d((InterfaceC1076h) uVar8.C1.get(), 0)), com.quizlet.featuregate.injection.a.d());
                    uVar8.Z();
                    rootActivity.h = uVar8.l0();
                    rootActivity.i = (com.quizlet.infra.legacysyncengine.managers.d) uVar8.Z.get();
                    rootActivity.j = (com.quizlet.braze.e) uVar8.X0.get();
                    rootActivity.k = (com.google.firebase.crashlytics.b) uVar8.t.get();
                    rootActivity.l = uVar8.a1();
                    rootActivity.m = new com.quizlet.features.notes.a((EventLogger) uVar8.l0.get(), 2);
                    rootActivity.n = uVar8.l1;
                    break;
                }
                break;
            case EventType.CDN /* 26 */:
                ClassCreationActivity classCreationActivity = (ClassCreationActivity) this.b;
                if (!classCreationActivity.g) {
                    classCreationActivity.g = true;
                    classCreationActivity.c = ((C4622e) ((com.quizlet.quizletandroid.ui.classcreation.e) classCreationActivity.d())).b.Q0();
                    break;
                }
                break;
            case 27:
                DeepLinkInterstitialActivity deepLinkInterstitialActivity = (DeepLinkInterstitialActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B10 = N6.b(deepLinkInterstitialActivity.getApplicationContext());
                if (componentCallbacks2B10 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B10 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B10).u()) && !deepLinkInterstitialActivity.o) {
                        deepLinkInterstitialActivity.o = true;
                        C4622e c4622e11 = (C4622e) ((com.quizlet.quizletandroid.ui.deeplinkinterstitial.f) deepLinkInterstitialActivity.d());
                        deepLinkInterstitialActivity.c = c4622e11.a();
                        com.quizlet.quizletandroid.u uVar9 = c4622e11.b;
                        deepLinkInterstitialActivity.e = uVar9.Q0();
                        deepLinkInterstitialActivity.p = (com.quizlet.quizletandroid.managers.c) uVar9.i1.get();
                        deepLinkInterstitialActivity.q = new com.quizlet.quizletandroid.managers.deeplinks.h();
                        break;
                    }
                }
                break;
            case 28:
                DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B11 = N6.b(diagramOverviewActivity.getApplicationContext());
                if (componentCallbacks2B11 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B11 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B11).u()) && !diagramOverviewActivity.p) {
                        diagramOverviewActivity.p = true;
                        C4622e c4622e12 = (C4622e) ((com.quizlet.quizletandroid.ui.diagramming.f) diagramOverviewActivity.d());
                        diagramOverviewActivity.c = c4622e12.a();
                        com.quizlet.quizletandroid.u uVar10 = c4622e12.b;
                        diagramOverviewActivity.e = uVar10.Q0();
                        uVar10.Z();
                        diagramOverviewActivity.F = uVar10.l0();
                        diagramOverviewActivity.G = (com.quizlet.quizletandroid.managers.audio.h) uVar10.f0.get();
                        diagramOverviewActivity.H = (com.quizlet.infra.legacysyncengine.net.f) uVar10.U.get();
                        diagramOverviewActivity.I = (com.quizlet.infra.legacysyncengine.net.c) uVar10.Q.get();
                        diagramOverviewActivity.J = (com.quizlet.infra.legacysyncengine.managers.d) uVar10.Z.get();
                        diagramOverviewActivity.K = com.quizlet.featuregate.injection.a.j();
                        diagramOverviewActivity.L = (com.quizlet.qutils.image.loading.a) uVar10.s.get();
                        diagramOverviewActivity.M = uVar10.g();
                        break;
                    }
                }
                break;
            default:
                GlobalNavigationActivity globalNavigationActivity = (GlobalNavigationActivity) this.b;
                ComponentCallbacks2 componentCallbacks2B12 = N6.b(globalNavigationActivity.getApplicationContext());
                if (componentCallbacks2B12 instanceof dagger.hilt.internal.b) {
                    if ((!(componentCallbacks2B12 instanceof dagger.hilt.android.internal.migration.a) || ((dagger.hilt.android.internal.migration.a) componentCallbacks2B12).u()) && !globalNavigationActivity.o) {
                        globalNavigationActivity.o = true;
                        C4622e c4622e13 = (C4622e) ((com.quizlet.quizletandroid.ui.globalnav.j) globalNavigationActivity.d());
                        globalNavigationActivity.c = c4622e13.a();
                        com.quizlet.quizletandroid.u uVar11 = c4622e13.b;
                        globalNavigationActivity.e = uVar11.Q0();
                        globalNavigationActivity.p = c4622e13.b();
                        globalNavigationActivity.q = new com.quizlet.data.repository.classfolder.e((com.quizlet.braze.e) uVar11.X0.get(), new PushNotificationLogger((EventLogger) uVar11.l0.get()));
                        break;
                    }
                }
                break;
        }
    }
}
