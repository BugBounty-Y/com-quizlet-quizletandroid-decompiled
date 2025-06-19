package com.quizlet.quizletandroid;

import android.app.Activity;
import android.content.Context;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.metering.StudyModeMeteringEventLogger;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4596d implements dagger.internal.c {
    public final u a;
    public final C4624g b;
    public final C4622e c;
    public final int d;

    public C4596d(u uVar, C4624g c4624g, C4622e c4622e, int i) {
        this.a = uVar;
        this.b = c4624g;
        this.c = c4622e;
        this.d = i;
    }

    @Override // javax.inject.a
    public final Object get() {
        int i = 2;
        int i2 = 26;
        int i3 = 1;
        int i4 = 0;
        C4624g c4624g = this.b;
        u uVar = this.a;
        C4622e c4622e = this.c;
        int i5 = this.d;
        switch (i5) {
            case 0:
                return new l(uVar, c4624g, c4622e, i4);
            case 1:
                return new m(uVar, c4624g, c4622e);
            case 2:
                return new C4625h(uVar, c4624g, c4622e);
            case 3:
                return new l(uVar, c4624g, c4622e, i3);
            case 4:
                return new l(uVar, c4624g, c4622e, i);
            case 5:
                return new com.quizlet.quizletandroid.ui.navigationmanagers.a(c4622e.a, uVar.l1);
            case 6:
                return new com.quizlet.quizletandroid.ui.studymodes.flashcards.navigation.a(c4622e.a);
            case 7:
                return new com.quizlet.quizletandroid.ui.profile.u(c4622e.a);
            case 8:
                return new com.quizlet.features.setpage.navigation.a(c4622e.a);
            case 9:
                return new com.quizlet.features.folders.navigation.a(c4622e.a);
            case 10:
                return new com.quizlet.quizletandroid.ui.share.a(c4622e.a, (com.quizlet.utmhelper.c) c4622e.o.get(), uVar.j());
            case 11:
                com.quizlet.shared.usecase.srs.a aVar = uVar.b;
                return new com.quizlet.utmhelper.d();
            case 12:
                return new com.quizlet.explanations.navigation.c(c4622e.a);
            case 13:
                return new com.quizlet.explanations.navigation.a(c4622e.a);
            case 14:
                return new com.quizlet.features.notes.navigation.a(c4622e.a);
            case 15:
                Activity activity = c4622e.a;
                u uVar2 = c4622e.b;
                return new com.quizlet.quizletandroid.ui.studymodes.assistant.navigation.b(activity, new com.quizlet.features.infra.basestudy.usecase.b(new com.quizlet.data.repository.studysetwithcreatorinclass.g(uVar2.l0(), (com.quizlet.infra.legacysyncengine.net.c) uVar2.Q.get(), uVar2.o1(), new com.quizlet.featuregate.features.studymodes.learn.a(i), uVar2.m0()), new com.google.firebase.perf.logging.b(i2), uVar2.m0(), new com.quizlet.data.interactor.metering.b(uVar2.w0(), uVar2.z0()), (com.quizlet.infra.legacysyncengine.managers.d) uVar2.Z.get()));
            case 16:
                return new com.quizlet.features.notes.navigation.b(c4622e.a);
            case 17:
                return new com.quizlet.upgrade.ui.navigation.a(c4622e.a);
            case 18:
                return new com.quizlet.quizletandroid.ui.report.a();
            case 19:
                Activity activity2 = c4622e.a;
                com.quizlet.quizletandroid.ui.webpages.a aVar2 = com.quizlet.quizletandroid.ui.webpages.a.a;
                return new com.quizlet.quizletandroid.ui.webpages.navigation.a(activity2);
            case 20:
                return new com.quizlet.login.navigation.a(c4622e.a);
            case 21:
                return new com.quizlet.features.paywall.d(c4622e.a);
            case EventType.WINDOW_STATE /* 22 */:
                Activity activity3 = c4622e.a;
                com.quizlet.quizletandroid.ui.webpages.a aVar3 = com.quizlet.quizletandroid.ui.webpages.a.a;
                return new com.quizlet.quizletandroid.ui.navigationmanagers.h(activity3, uVar.l1, (com.quizlet.features.consent.onetrust.d) uVar.R0.get());
            case EventType.AUDIO /* 23 */:
                Activity activity4 = c4622e.a;
                Context context = uVar.q();
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(context, "context");
                androidx.credentials.f fVar = new androidx.credentials.f(context);
                String serverClientId = uVar.a0();
                Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
                Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
                com.google.android.libraries.identity.googleid.b credentialOption = new com.google.android.libraries.identity.googleid.b(serverClientId);
                Intrinsics.checkNotNullParameter(credentialOption, "getGoogleIdOption");
                ArrayList arrayList = new ArrayList();
                Intrinsics.checkNotNullParameter(credentialOption, "credentialOption");
                arrayList.add(credentialOption);
                androidx.credentials.o oVar = new androidx.credentials.o(CollectionsKt.w0(arrayList));
                String serverClientId2 = uVar.a0();
                Intrinsics.checkNotNullParameter(serverClientId2, "serverClientId");
                Intrinsics.checkNotNullParameter(serverClientId2, "serverClientId");
                if (serverClientId2.length() <= 0) {
                    throw new IllegalArgumentException("serverClientId should not be empty");
                }
                com.google.android.libraries.identity.googleid.a credentialOption2 = new com.google.android.libraries.identity.googleid.a(serverClientId2, false);
                Intrinsics.checkNotNullParameter(credentialOption2, "getGoogleIdOption");
                ArrayList arrayList2 = new ArrayList();
                Intrinsics.checkNotNullParameter(credentialOption2, "credentialOption");
                arrayList2.add(credentialOption2);
                androidx.credentials.o oVar2 = new androidx.credentials.o(CollectionsKt.w0(arrayList2));
                String serverClientId3 = uVar.a0();
                Intrinsics.checkNotNullParameter(serverClientId3, "serverClientId");
                Intrinsics.checkNotNullParameter(serverClientId3, "serverClientId");
                if (serverClientId3.length() <= 0) {
                    throw new IllegalArgumentException("serverClientId should not be empty");
                }
                com.google.android.libraries.identity.googleid.a credentialOption3 = new com.google.android.libraries.identity.googleid.a(serverClientId3, true);
                Intrinsics.checkNotNullParameter(credentialOption3, "getGoogleIdOption");
                ArrayList arrayList3 = new ArrayList();
                Intrinsics.checkNotNullParameter(credentialOption3, "credentialOption");
                arrayList3.add(credentialOption3);
                androidx.credentials.o oVar3 = new androidx.credentials.o(CollectionsKt.w0(arrayList3));
                com.quizlet.shared.usecase.srs.a aVar4 = new com.quizlet.shared.usecase.srs.a(i2);
                GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
                Intrinsics.checkNotNullExpressionValue(googleApiAvailability, "getInstance(...)");
                S6.c(googleApiAvailability);
                return new com.quizlet.features.infra.google.e(activity4, fVar, oVar, oVar2, oVar3, aVar4, googleApiAvailability);
            case EventType.VIDEO /* 24 */:
                return new com.quizlet.features.practicetest.navigation.j(c4622e.a);
            case EventType.SUBS /* 25 */:
                return new com.quizlet.quizletandroid.ui.profile.a(c4622e.a);
            case EventType.CDN /* 26 */:
                return new com.quizlet.features.settings.navigation.a(c4622e.a);
            case 27:
                return new com.quizlet.features.achievements.navigation.b(c4622e.a);
            case 28:
                return new com.quizlet.quizletandroid.ui.activitycenter.navigation.a(c4622e.a);
            case 29:
                Activity activity5 = c4622e.a;
                com.quizlet.quizletandroid.ui.webpages.a aVar5 = com.quizlet.quizletandroid.ui.webpages.a.a;
                return new com.quizlet.quizletandroid.ui.navigationmanagers.d(activity5, (com.quizlet.quizletandroid.util.g) uVar.B1.get(), new com.quizlet.quizletandroid.ui.debug.a());
            case 30:
                return new com.quizlet.quizletandroid.ui.classcreation.navigation.a(c4622e.a);
            case 31:
                return new com.quizlet.features.consent.onetrust.navigation.a(uVar.R0);
            case 32:
                return new com.quizlet.features.infra.folder.create.navigation.a();
            case 33:
                return new com.quizlet.quizletandroid.ui.startpage.nav2.navigation.a();
            case 34:
                return new com.quizlet.edgy.navigation.a();
            case 35:
                return new com.quizlet.features.userprofile.navigation.a(c4622e.a);
            case 36:
                return new com.quizlet.login.magiclink.navigation.a();
            case 37:
                return new com.quizlet.features.onboarding.navigation.a(c4622e.a);
            case 38:
                return new com.quizlet.quizletandroid.ui.group.navigation.a(c4622e.a);
            case 39:
                return new com.quizlet.quizletandroid.ui.search.navigation.a(c4622e.a);
            case RequestError.NETWORK_FAILURE /* 40 */:
                return new com.quizlet.quizletandroid.ui.subject.navigation.a(c4622e.a);
            case RequestError.NO_DEV_KEY /* 41 */:
                return new com.quizlet.features.onboarding.ell.o();
            case 42:
                com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                StudyModeMeteringEventLogger studyModeMeteringEventLogger = new StudyModeMeteringEventLogger((EventLogger) c4622e.b.l0.get());
                u uVar3 = c4622e.b;
                return new com.quizlet.quizletandroid.ui.learnpaywall.k(dVar, studyModeMeteringEventLogger, new androidx.work.impl.model.e(uVar3.R(), uVar3.m0()));
            case 43:
                com.quizlet.quizletandroid.ui.webpages.a aVar6 = com.quizlet.quizletandroid.ui.webpages.a.a;
                return new com.quizlet.quizletandroid.ui.navigationmanagers.c(c4622e.a);
            case 44:
                return new C4595c(this);
            case 45:
                Activity activity6 = c4622e.a;
                com.quizlet.quizletandroid.ui.webpages.a aVar7 = com.quizlet.quizletandroid.ui.webpages.a.a;
                return new com.quizlet.quizletandroid.ui.navigationmanagers.b(activity6, uVar.H1);
            default:
                throw new AssertionError(i5);
        }
    }
}
