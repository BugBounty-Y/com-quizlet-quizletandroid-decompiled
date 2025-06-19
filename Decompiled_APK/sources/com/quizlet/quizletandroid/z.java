package com.quizlet.quizletandroid;

import android.content.Context;
import android.os.Build;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.foundation.lazy.layout.C0429a;
import androidx.compose.ui.node.V;
import androidx.datastore.core.InterfaceC1076h;
import androidx.lifecycle.m0;
import com.braze.Braze;
import com.comscore.streaming.ContentType;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.measurement.internal.J;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.util.ApiErrorResolverWrapper;
import com.quizlet.api.util.OneOffAPIParser;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionLogger;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLogger;
import com.quizlet.eventlogger.features.deeplink.DeepLinkEventLogger;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.local.datastore.preferences.AbstractC4575k;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.local.datastore.preferences.C4574j;
import com.quizlet.local.datastore.preferences.k0;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class z implements dagger.hilt.android.internal.lifecycle.e, dagger.hilt.internal.a {
    public final y A;
    public final y A0;
    public final y A1;
    public final y B;
    public final y B0;
    public final y B1;
    public final y C;
    public final y C0;
    public final y C1;
    public final dagger.internal.c D;
    public final dagger.internal.c D0;
    public final y D1;
    public final y E;
    public final y E0;
    public final dagger.internal.c E1;
    public final y F;
    public final y F0;
    public final y F1;
    public final y G;
    public final y G0;
    public final y G1;
    public final y H;
    public final y H0;
    public final y H1;
    public final y I;
    public final y I0;
    public final y I1;
    public final y J;
    public final y J0;
    public final y J1;
    public final y K;
    public final y K0;
    public final y K1;
    public final y L;
    public final y L0;
    public final y L1;
    public final y M;
    public final y M0;
    public final y M1;
    public final y N;
    public final y N0;
    public final y N1;
    public final y O;
    public final y O0;
    public final y O1;
    public final y P;
    public final y P0;
    public final y P1;
    public final y Q;
    public final y Q0;
    public final y Q1;
    public final y R;
    public final y R0;
    public final y R1;
    public final y S;
    public final y S0;
    public final y S1;
    public final y T;
    public final y T0;
    public final y T1;
    public final y U;
    public final y U0;
    public final y U1;
    public final y V;
    public final y V0;
    public final y V1;
    public final y W;
    public final y W0;
    public final y W1;
    public final y X;
    public final y X0;
    public final y X1;
    public final y Y;
    public final y Y0;
    public final y Y1;
    public final y Z;
    public final y Z0;
    public final y Z1;
    public final m0 a;
    public final y a0;
    public final y a1;
    public final y a2;
    public final u b;
    public final y b0;
    public final y b1;
    public final y b2;
    public final C4624g c;
    public final y c0;
    public final dagger.internal.c c1;
    public final y c2;
    public final y d;
    public final y d0;
    public final dagger.internal.c d1;
    public final y e;
    public final y e0;
    public final y e1;
    public final y f;
    public final y f0;
    public final y f1;
    public final y g;
    public final y g0;
    public final y g1;
    public final y h;
    public final y h0;
    public final y h1;
    public final y i;
    public final y i0;
    public final y i1;
    public final y j;
    public final dagger.internal.c j0;
    public final y j1;
    public final y k;
    public final y k0;
    public final y k1;
    public final y l;
    public final y l0;
    public final y l1;
    public final y m;
    public final y m0;
    public final y m1;
    public final dagger.internal.c n;
    public final y n0;
    public final y n1;
    public final y o;
    public final y o0;
    public final y o1;
    public final y p;
    public final y p0;
    public final y p1;
    public final y q;
    public final y q0;
    public final y q1;
    public final y r;
    public final y r0;
    public final y r1;
    public final y s;
    public final y s0;
    public final y s1;
    public final y t;
    public final y t0;
    public final y t1;
    public final y u;
    public final y u0;
    public final dagger.internal.c u1;
    public final y v;
    public final y v0;
    public final dagger.internal.c v1;
    public final y w;
    public final y w0;
    public final y w1;
    public final y x;
    public final y x0;
    public final y x1;
    public final y y;
    public final y y0;
    public final y y1;
    public final y z;
    public final y z0;
    public final y z1;

    public z(u uVar, C4624g c4624g, m0 m0Var) {
        this.b = uVar;
        this.c = c4624g;
        this.a = m0Var;
        this.d = new y(uVar, c4624g, this, 0);
        this.e = new y(uVar, c4624g, this, 2);
        this.f = new y(uVar, c4624g, this, 1);
        this.g = new y(uVar, c4624g, this, 3);
        this.h = new y(uVar, c4624g, this, 4);
        this.i = new y(uVar, c4624g, this, 5);
        this.j = new y(uVar, c4624g, this, 6);
        this.k = new y(uVar, c4624g, this, 7);
        this.l = new y(uVar, c4624g, this, 8);
        this.m = new y(uVar, c4624g, this, 9);
        this.n = dagger.internal.d.a(new y(uVar, c4624g, this, 11));
        this.o = new y(uVar, c4624g, this, 10);
        this.p = new y(uVar, c4624g, this, 12);
        this.q = new y(uVar, c4624g, this, 13);
        this.r = new y(uVar, c4624g, this, 14);
        this.s = new y(uVar, c4624g, this, 15);
        this.t = new y(uVar, c4624g, this, 16);
        this.u = new y(uVar, c4624g, this, 17);
        this.v = new y(uVar, c4624g, this, 18);
        this.w = new y(uVar, c4624g, this, 19);
        this.x = new y(uVar, c4624g, this, 20);
        this.y = new y(uVar, c4624g, this, 21);
        this.z = new y(uVar, c4624g, this, 22);
        this.A = new y(uVar, c4624g, this, 23);
        this.B = new y(uVar, c4624g, this, 24);
        this.C = new y(uVar, c4624g, this, 25);
        this.D = dagger.internal.d.a(new y(uVar, c4624g, this, 27));
        this.E = new y(uVar, c4624g, this, 26);
        this.F = new y(uVar, c4624g, this, 28);
        this.G = new y(uVar, c4624g, this, 29);
        this.H = new y(uVar, c4624g, this, 30);
        this.I = new y(uVar, c4624g, this, 31);
        this.J = new y(uVar, c4624g, this, 32);
        this.K = new y(uVar, c4624g, this, 33);
        this.L = new y(uVar, c4624g, this, 34);
        this.M = new y(uVar, c4624g, this, 35);
        this.N = new y(uVar, c4624g, this, 36);
        this.O = new y(uVar, c4624g, this, 37);
        this.P = new y(uVar, c4624g, this, 38);
        this.Q = new y(uVar, c4624g, this, 39);
        this.R = new y(uVar, c4624g, this, 40);
        this.S = new y(uVar, c4624g, this, 41);
        this.T = new y(uVar, c4624g, this, 42);
        this.U = new y(uVar, c4624g, this, 43);
        this.V = new y(uVar, c4624g, this, 44);
        this.W = new y(uVar, c4624g, this, 45);
        this.X = new y(uVar, c4624g, this, 46);
        this.Y = new y(uVar, c4624g, this, 47);
        this.Z = new y(uVar, c4624g, this, 48);
        this.a0 = new y(uVar, c4624g, this, 49);
        this.b0 = new y(uVar, c4624g, this, 51);
        this.c0 = new y(uVar, c4624g, this, 50);
        this.d0 = new y(uVar, c4624g, this, 52);
        this.e0 = new y(uVar, c4624g, this, 53);
        this.f0 = new y(uVar, c4624g, this, 54);
        this.g0 = new y(uVar, c4624g, this, 55);
        this.h0 = new y(uVar, c4624g, this, 56);
        this.i0 = new y(uVar, c4624g, this, 57);
        this.j0 = dagger.internal.d.a(new y(uVar, c4624g, this, 59));
        this.k0 = new y(uVar, c4624g, this, 58);
        this.l0 = new y(uVar, c4624g, this, 60);
        this.m0 = new y(uVar, c4624g, this, 61);
        this.n0 = new y(uVar, c4624g, this, 62);
        this.o0 = new y(uVar, c4624g, this, 63);
        this.p0 = new y(uVar, c4624g, this, 64);
        this.q0 = new y(uVar, c4624g, this, 65);
        this.r0 = new y(uVar, c4624g, this, 66);
        this.s0 = new y(uVar, c4624g, this, 67);
        this.t0 = new y(uVar, c4624g, this, 68);
        this.u0 = new y(uVar, c4624g, this, 69);
        this.v0 = new y(uVar, c4624g, this, 70);
        this.w0 = new y(uVar, c4624g, this, 71);
        this.x0 = new y(uVar, c4624g, this, 72);
        this.y0 = new y(uVar, c4624g, this, 73);
        this.z0 = new y(uVar, c4624g, this, 74);
        this.A0 = new y(uVar, c4624g, this, 75);
        this.B0 = new y(uVar, c4624g, this, 76);
        this.C0 = new y(uVar, c4624g, this, 77);
        this.D0 = dagger.internal.d.a(new y(uVar, c4624g, this, 79));
        this.E0 = new y(uVar, c4624g, this, 78);
        this.F0 = new y(uVar, c4624g, this, 80);
        this.G0 = new y(uVar, c4624g, this, 81);
        this.H0 = new y(uVar, c4624g, this, 82);
        this.I0 = new y(uVar, c4624g, this, 83);
        this.J0 = new y(uVar, c4624g, this, 84);
        this.K0 = new y(uVar, c4624g, this, 85);
        this.L0 = new y(uVar, c4624g, this, 86);
        this.M0 = new y(uVar, c4624g, this, 87);
        this.N0 = new y(uVar, c4624g, this, 88);
        this.O0 = new y(uVar, c4624g, this, 89);
        this.P0 = new y(uVar, c4624g, this, 90);
        this.Q0 = new y(uVar, c4624g, this, 91);
        this.R0 = new y(uVar, c4624g, this, 92);
        this.S0 = new y(uVar, c4624g, this, 93);
        this.T0 = new y(uVar, c4624g, this, 94);
        this.U0 = new y(uVar, c4624g, this, 95);
        this.V0 = new y(uVar, c4624g, this, 96);
        this.W0 = new y(uVar, c4624g, this, 97);
        this.X0 = new y(uVar, c4624g, this, 98);
        this.Y0 = new y(uVar, c4624g, this, 99);
        this.Z0 = new y(uVar, c4624g, this, 100);
        this.a1 = new y(uVar, c4624g, this, 101);
        this.b1 = new y(uVar, c4624g, this, 102);
        this.c1 = dagger.internal.d.a(new y(uVar, c4624g, this, 104));
        this.d1 = dagger.internal.d.a(new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED));
        this.e1 = new y(uVar, c4624g, this, 103);
        this.f1 = new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF);
        this.g1 = new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED);
        this.h1 = new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
        this.i1 = new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION);
        this.j1 = new y(uVar, c4624g, this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED);
        this.k1 = new y(uVar, c4624g, this, 111);
        this.l1 = new y(uVar, c4624g, this, ContentType.LONG_FORM_ON_DEMAND);
        this.m1 = new y(uVar, c4624g, this, ContentType.LIVE);
        this.n1 = new y(uVar, c4624g, this, 114);
        this.o1 = new y(uVar, c4624g, this, 115);
        this.p1 = new y(uVar, c4624g, this, 116);
        this.q1 = new y(uVar, c4624g, this, 117);
        this.r1 = new y(uVar, c4624g, this, 118);
        this.s1 = new y(uVar, c4624g, this, 119);
        this.t1 = new y(uVar, c4624g, this, 120);
        this.u1 = dagger.internal.d.a(new y(uVar, c4624g, this, ContentType.USER_GENERATED_LIVE));
        this.v1 = dagger.internal.d.a(new y(uVar, c4624g, this, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND));
        this.w1 = new y(uVar, c4624g, this, ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND);
        this.x1 = new y(uVar, c4624g, this, 124);
        this.y1 = new y(uVar, c4624g, this, 125);
        this.z1 = new y(uVar, c4624g, this, 126);
        this.A1 = new y(uVar, c4624g, this, 127);
        this.B1 = new y(uVar, c4624g, this, 128);
        this.C1 = new y(uVar, c4624g, this, 129);
        this.D1 = new y(uVar, c4624g, this, 130);
        this.E1 = dagger.internal.d.a(new y(uVar, c4624g, this, 132));
        this.F1 = new y(uVar, c4624g, this, 131);
        this.G1 = new y(uVar, c4624g, this, 133);
        this.H1 = new y(uVar, c4624g, this, 134);
        this.I1 = new y(uVar, c4624g, this, 135);
        this.J1 = new y(uVar, c4624g, this, 136);
        this.K1 = new y(uVar, c4624g, this, 137);
        this.L1 = new y(uVar, c4624g, this, 138);
        this.M1 = new y(uVar, c4624g, this, 139);
        this.N1 = new y(uVar, c4624g, this, 140);
        this.O1 = new y(uVar, c4624g, this, ModuleDescriptor.MODULE_VERSION);
        this.P1 = new y(uVar, c4624g, this, 143);
        this.Q1 = new y(uVar, c4624g, this, 144);
        this.R1 = new y(uVar, c4624g, this, 145);
        this.S1 = new y(uVar, c4624g, this, 142);
        this.T1 = new y(uVar, c4624g, this, 146);
        this.U1 = new y(uVar, c4624g, this, 147);
        this.V1 = new y(uVar, c4624g, this, 148);
        this.W1 = new y(uVar, c4624g, this, 149);
        this.X1 = new y(uVar, c4624g, this, 150);
        this.Y1 = new y(uVar, c4624g, this, 151);
        this.Z1 = new y(uVar, c4624g, this, 152);
        this.a2 = new y(uVar, c4624g, this, 153);
        this.b2 = new y(uVar, c4624g, this, 154);
        this.c2 = new y(uVar, c4624g, this, 155);
    }

    public static com.quizlet.data.repository.login.a C() {
        com.quizlet.features.questiontypes.basequestion.c answerLabelUseCase = new com.quizlet.features.questiontypes.basequestion.c();
        Intrinsics.checkNotNullParameter(answerLabelUseCase, "answerLabelUseCase");
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        aVar.a = answerLabelUseCase;
        return aVar;
    }

    public final com.quizlet.data.repository.studysetwithcreatorinclass.g A() {
        return new com.quizlet.data.repository.studysetwithcreatorinclass.g(this.b.q(), com.quizlet.featuregate.injection.a.d());
    }

    public final androidx.work.impl.model.l A0() {
        u uVar = this.b;
        return new androidx.work.impl.model.l((EventLogger) uVar.l0.get(), new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.d(new com.quizlet.quizletandroid.managers.upgrade.a(1), new com.google.android.gms.internal.mlkit_common.u(false), (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get()));
    }

    public final ExplanationsLogger B() {
        u uVar = this.b;
        return new ExplanationsLogger((EventLogger) uVar.l0.get(), new StudyFunnelEventLogger((EventLogger) uVar.l0.get()));
    }

    public final com.quizlet.data.repository.course.membership.c B0() {
        com.quizlet.quizletandroid.managers.upgrade.a aVar = new com.quizlet.quizletandroid.managers.upgrade.a(1);
        u uVar = this.b;
        return new com.quizlet.data.repository.course.membership.c(aVar, (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), (EventLogger) uVar.l0.get());
    }

    public final com.google.firebase.crashlytics.internal.common.j C0() {
        u uVar = this.b;
        return new com.google.firebase.crashlytics.internal.common.j(new com.quizlet.data.interactor.folderstudymaterial.z(new com.google.firebase.crashlytics.internal.settings.b(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.quizlet.data.interactor.achievements.f(new com.google.firebase.messaging.p(new com.quizlet.data.repository.qclass.c(uVar.K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.google.firebase.perf.logging.b(24)));
    }

    public final com.quizlet.features.flashcards.engine.h D() {
        com.quizlet.features.infra.basestudy.manager.a aVar = (com.quizlet.features.infra.basestudy.manager.a) this.c.j.get();
        u uVar = this.b;
        com.quizlet.data.interactor.achievements.f fVar = new com.quizlet.data.interactor.achievements.f(uVar.j1());
        com.quizlet.shared.usecase.folderstudymaterials.b bVar = new com.quizlet.shared.usecase.folderstudymaterials.b(26);
        com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        com.quizlet.data.repository.explanations.textbook.a aVar2 = new com.quizlet.data.repository.explanations.textbook.a();
        aVar2.a = loader;
        aVar2.b = loggedInUserManager;
        return new com.quizlet.features.flashcards.engine.h(this.a, aVar, fVar, bVar, aVar2, new com.quizlet.data.interactor.school.b((com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get()), new com.quizlet.features.flashcards.logging.a((EventLogger) uVar.l0.get()), (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get(), new com.quizlet.features.flashcards.logging.b((EventLogger) uVar.l0.get()), com.quizlet.featuregate.injection.a.d());
    }

    public final com.quizlet.data.repository.qclass.c D0() {
        u uVar = this.b;
        com.quizlet.remote.service.x xVarJ0 = uVar.j0();
        com.quizlet.remote.model.school.a schoolMapper = new com.quizlet.remote.model.school.a();
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        return new com.quizlet.data.repository.qclass.c(new com.quizlet.data.repository.school.membership.a(new com.quizlet.remote.model.school.h(xVarJ0, new com.quizlet.remote.model.school.memberships.a(), com.quizlet.featuregate.injection.a.d())), u.v(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.school.membership.a.class, "getLogger(...)"));
    }

    public final androidx.work.impl.model.v E() {
        return new androidx.work.impl.model.v((InterfaceC1076h) this.b.P1.get());
    }

    public final com.quizlet.data.repository.achievements.h E0() {
        com.quizlet.shared.usecase.studiableMetadata.a globalAdFeature = new com.quizlet.shared.usecase.studiableMetadata.a(25);
        u uVar = this.b;
        androidx.work.impl.model.c userProperties = uVar.m0();
        com.quizlet.data.repository.folderwithcreator.e searchMultiAdFetcher = new com.quizlet.data.repository.folderwithcreator.e(new com.google.mlkit.vision.documentscanner.internal.c(uVar.v0), uVar.o0(), new com.quizlet.ads.helper.b(uVar.q()));
        Context context = uVar.q();
        Intrinsics.checkNotNullParameter(globalAdFeature, "globalAdFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(searchMultiAdFetcher, "searchMultiAdFetcher");
        Intrinsics.checkNotNullParameter(context, "context");
        com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h();
        hVar.a = globalAdFeature;
        hVar.b = userProperties;
        hVar.c = searchMultiAdFetcher;
        hVar.d = context;
        return hVar;
    }

    public final com.quizlet.features.flashcards.logging.d F() {
        return new com.quizlet.features.flashcards.logging.d((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.repository.activitycenter.b F0() {
        return new com.quizlet.data.repository.activitycenter.b(new com.quizlet.login.common.interactors.d(this.b.A(), new com.quizlet.quizletandroid.ui.setcreation.adapters.a(1)), u.v());
    }

    public final com.google.firebase.crashlytics.internal.common.j G() {
        return new com.google.firebase.crashlytics.internal.common.j(this.b.b());
    }

    public final com.quizlet.features.emailconfirmation.logging.a G0() {
        return new com.quizlet.features.emailconfirmation.logging.a((EventLogger) this.b.l0.get(), 1);
    }

    public final com.google.android.material.floatingactionbutton.c H() {
        return new com.google.android.material.floatingactionbutton.c(this.c.a());
    }

    public final com.quizlet.data.repository.searchexplanations.c H0() {
        return new com.quizlet.data.repository.searchexplanations.c(this.b.l0(), (com.quizlet.utmhelper.c) this.D.get());
    }

    public final J I() {
        u uVar = this.b;
        return new J(uVar.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), uVar.m1(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.features.flashcards.creatormarketing.o I0() {
        u uVar = this.b;
        Context context = uVar.q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = AbstractC4575k.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        C4574j c4574j = new C4574j((InterfaceC1076h) AbstractC4575k.b.a(context, AbstractC4575k.a[0]), 0);
        long j = uVar.j();
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
        com.quizlet.data.repository.user.a aVarI = AbstractC4178x.i(aVar, "growthBook", "creator_retention_modal_android", aVar);
        com.quizlet.infra.contracts.growthbook.a growthBook = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
        Intrinsics.checkNotNullParameter(growthBook, "growthBook");
        com.quizlet.data.repository.explanations.question.a aVar2 = new com.quizlet.data.repository.explanations.question.a(growthBook, "creator_retention_modal_session_threshold", (Integer) 0);
        com.quizlet.infra.contracts.growthbook.a growthBook2 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
        Intrinsics.checkNotNullParameter(growthBook2, "growthBook");
        return new com.features.flashcards.creatormarketing.o(c4574j, j, aVarI, aVar2, new com.quizlet.data.repository.explanations.question.a(growthBook2, "creator_retention_modal_frequency_interval_in_days", (Integer) 0));
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, kotlin.k] */
    public final l1 J() {
        com.quizlet.shared.usecase.studynotes.t tVar = (com.quizlet.shared.usecase.studynotes.t) com.quizlet.shared.usecase.di.f.d.getValue();
        S6.c(tVar);
        return new l1(new com.quizlet.data.interactor.notes.f(tVar, f0()), this.b.j());
    }

    public final com.lyft.android.scissors.b J0() {
        return new com.lyft.android.scissors.b(new androidx.work.impl.model.l(this.b.F(), com.quizlet.featuregate.injection.a.d()));
    }

    public final V K() {
        u uVar = this.b;
        androidx.work.impl.model.v vVar = new androidx.work.impl.model.v(uVar.N(), com.quizlet.featuregate.injection.a.d());
        UserInfoCache userInfoCacheL0 = uVar.l0();
        com.quizlet.data.connectivity.a aVar = (com.quizlet.data.connectivity.a) uVar.X.get();
        com.quizlet.data.repository.course.membership.c cVarR = uVar.r();
        com.quizlet.data.repository.activitycenter.b bVarO = o();
        com.quizlet.data.repository.user.a aVarP1 = uVar.p1();
        com.quizlet.infra.contracts.growthbook.a aVar2 = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
        return new V(vVar, userInfoCacheL0, aVar, cVarR, bVarO, aVarP1, AbstractC4178x.i(aVar2, "growthBook", "QuizletPoweredFolders", aVar2), new com.google.android.material.floatingactionbutton.c(new com.quizlet.data.repository.activitycenter.b(uVar.F(), com.quizlet.featuregate.injection.a.d())));
    }

    public final com.quizlet.local.ormlite.models.term.b K0() {
        return new com.quizlet.local.ormlite.models.term.b((EventLogger) this.b.l0.get());
    }

    public final com.onetrust.otpublishers.headless.UI.fragment.q L() {
        return new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.quizletandroid.util.o(this.b.q()));
    }

    public final com.quizlet.features.universaluploadflow.logging.b L0() {
        return new com.quizlet.features.universaluploadflow.logging.b(this.a, (EventLogger) this.b.l0.get());
    }

    public final com.onetrust.otpublishers.headless.UI.fragment.q M() {
        return new com.onetrust.otpublishers.headless.UI.fragment.q(this.b.U0());
    }

    public final com.quizlet.login.common.interactors.d M0() {
        return new com.quizlet.login.common.interactors.d(l0());
    }

    public final l1 N() {
        u uVar = this.b;
        return new l1(new com.quizlet.quizletandroid.interactor.m(uVar.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), new assistantMode.utils.studiableMetadata.b(29), com.quizlet.featuregate.injection.a.d()), uVar.j());
    }

    public final com.google.android.gms.internal.appset.e N0() {
        return new com.google.android.gms.internal.appset.e(dagger.internal.a.a(this.P1), dagger.internal.a.a(this.Q1), dagger.internal.a.a(this.R1));
    }

    public final com.quizlet.data.repository.qclass.c O() {
        u uVar = this.b;
        com.google.mlkit.vision.documentscanner.internal.c imageRefDataSourceFactory = new com.google.mlkit.vision.documentscanner.internal.c((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get());
        com.quizlet.infra.legacysyncengine.datasources.d diagramShapeDataSourceFactory = new com.quizlet.infra.legacysyncengine.datasources.d((com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), 0);
        Intrinsics.checkNotNullParameter(imageRefDataSourceFactory, "imageRefDataSourceFactory");
        Intrinsics.checkNotNullParameter(diagramShapeDataSourceFactory, "diagramShapeDataSourceFactory");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
        jVar.a = imageRefDataSourceFactory;
        jVar.b = diagramShapeDataSourceFactory;
        return new com.quizlet.data.repository.qclass.c(jVar, com.quizlet.featuregate.injection.a.d());
    }

    public final com.quizlet.data.repository.qclass.c O0() {
        return new com.quizlet.data.repository.qclass.c((com.quizlet.quizletandroid.ui.usersettings.d) this.n.get(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.lyft.android.scissors.b P() {
        u uVar = this.b;
        uVar.getClass();
        return new com.lyft.android.scissors.b(new com.quizlet.data.repository.activitycenter.b(com.quizlet.featuregate.injection.a.d(), (com.quizlet.data.connectivity.a) uVar.X.get()));
    }

    public final com.quizlet.features.setpage.logging.writetransition.a P0() {
        return new com.quizlet.features.setpage.logging.writetransition.a((EventLogger) this.b.l0.get());
    }

    public final io.ktor.client.plugins.api.d Q() {
        u uVar = this.b;
        return new io.ktor.client.plugins.api.d(uVar.r(), new com.quizlet.data.interactor.folder.c(uVar.G(), com.quizlet.featuregate.injection.a.d(), 1), new C0429a(uVar.j()));
    }

    public final com.quizlet.features.folders.viewmodel.usecases.k R() {
        u uVar = this.b;
        return new com.quizlet.features.folders.viewmodel.usecases.k(uVar.T(), new C0429a(uVar.j()));
    }

    public final com.quizlet.features.infra.basestudy.usecase.b S() {
        u uVar = this.b;
        return new com.quizlet.features.infra.basestudy.usecase.b(new com.quizlet.data.repository.studysetwithcreatorinclass.g(uVar.l0(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get(), uVar.o1(), new com.quizlet.featuregate.features.studymodes.learn.a(2), uVar.m0()), new com.google.firebase.perf.logging.b(26), uVar.m0(), V(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get());
    }

    public final com.quizlet.login.authentication.login.a T() {
        com.quizlet.featuregate.features.studymodes.learn.a aVar = new com.quizlet.featuregate.features.studymodes.learn.a(3);
        u uVar = this.b;
        return new com.quizlet.login.authentication.login.a(new J(aVar, uVar.m0(), V(), uVar.j()));
    }

    public final com.quizlet.quizletandroid.ui.setcreation.managers.n U() {
        com.quizlet.featuregate.features.studymodes.learn.a aVar = new com.quizlet.featuregate.features.studymodes.learn.a(3);
        u uVar = this.b;
        return new com.quizlet.quizletandroid.ui.setcreation.managers.n(new J(aVar, uVar.m0(), V(), uVar.j()));
    }

    public final com.quizlet.data.interactor.metering.b V() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.metering.b(uVar.w0(), uVar.z0());
    }

    public final com.google.firebase.messaging.p W() {
        return new com.google.firebase.messaging.p(new com.quizlet.data.repository.explanations.myexplanations.a(this.b.x0(), u.v()));
    }

    public final com.quizlet.data.interactor.course.e X() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.course.e(uVar.L0(), uVar.j(), new com.quizlet.quizletandroid.util.o(uVar.q()));
    }

    public final com.quizlet.data.interactor.progress.c Y() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.progress.c(uVar.M0(), uVar.N0(), u.v(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.interactor.progress.c.class, "getLogger(...)"));
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, kotlin.k] */
    public final com.quizlet.data.interactor.studiablemetadata.b Z() {
        com.quizlet.shared.usecase.studiableMetadata.g gVar = (com.quizlet.shared.usecase.studiableMetadata.g) com.quizlet.shared.usecase.di.b.a.getValue();
        S6.c(gVar);
        return new com.quizlet.data.interactor.studiablemetadata.b(gVar, AbstractC4178x.o((org.slf4j.a) this.b.Y.get(), "loggerFactory", com.quizlet.data.interactor.studiablemetadata.b.class, "getLogger(...)"));
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, kotlin.k] */
    public final com.quizlet.data.repository.login.a a0() {
        com.quizlet.shared.usecase.studynotes.s getStudyNotesByIdUseCase = (com.quizlet.shared.usecase.studynotes.s) com.quizlet.shared.usecase.di.f.e.getValue();
        S6.c(getStudyNotesByIdUseCase);
        com.quizlet.data.interactor.set.c getUserUseCase = f0();
        com.quizlet.cache.a cache = (com.quizlet.cache.a) this.b.O1.get();
        Intrinsics.checkNotNullParameter(getStudyNotesByIdUseCase, "getStudyNotesByIdUseCase");
        Intrinsics.checkNotNullParameter(getUserUseCase, "getUserUseCase");
        Intrinsics.checkNotNullParameter(cache, "cache");
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        aVar.a = getStudyNotesByIdUseCase;
        aVar.b = getUserUseCase;
        aVar.c = cache;
        return aVar;
    }

    public final com.quizlet.data.interactor.achievements.f b() {
        return new com.quizlet.data.interactor.achievements.f(this.b.b());
    }

    public final io.ktor.client.plugins.api.d b0() {
        return new io.ktor.client.plugins.api.d(this.b.l1(), u.v(), (com.quizlet.cache.a) this.c.t.get());
    }

    public final com.onetrust.otpublishers.headless.UI.fragment.q c() {
        return new com.onetrust.otpublishers.headless.UI.fragment.q(this.b.b());
    }

    public final com.google.android.gms.internal.appset.e c0() {
        u uVar = this.b;
        return new com.google.android.gms.internal.appset.e(uVar.p1(), uVar.T(), new C0429a(uVar.j()));
    }

    public final AchievementsToastInteractionLogger d() {
        return new AchievementsToastInteractionLogger((EventLogger) this.b.l0.get());
    }

    public final androidx.work.impl.model.e d0() {
        u uVar = this.b;
        com.quizlet.data.repository.set.f fVar = new com.quizlet.data.repository.set.f(uVar.R0(), (ModelIdentityProvider) uVar.B.get(), new com.quizlet.local.ormlite.models.term.a());
        L l = (L) uVar.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.C.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.C c = (com.quizlet.remote.service.C) objL;
        S6.c(c);
        return new androidx.work.impl.model.e(new com.quizlet.data.repository.term.g(fVar, new com.quizlet.data.repository.classfolder.e(new C4636c(c), new com.quizlet.quizletandroid.ui.setcreation.adapters.a(3), new com.quizlet.remote.model.base.b()), (com.quizlet.data.connectivity.a) uVar.X.get(), com.quizlet.featuregate.injection.a.d(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.term.g.class, "getLogger(...)")), u.v());
    }

    public final com.quizlet.data.repository.explanations.myexplanations.a e() {
        u uVar = this.b;
        return new com.quizlet.data.repository.explanations.myexplanations.a(uVar.q(), (EventLogger) uVar.l0.get());
    }

    public final com.quizlet.data.repository.classmembership.c e0() {
        u uVar = this.b;
        return new com.quizlet.data.repository.classmembership.c(uVar.l0(), uVar.m0(), new com.quizlet.featuregate.features.home.a(), this.c.d());
    }

    public final com.quizlet.data.repository.activitycenter.b f() {
        L l = (L) this.b.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.j.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.j jVar = (com.quizlet.remote.service.j) objL;
        S6.c(jVar);
        com.quizlet.login.common.interactors.d dVar = new com.quizlet.login.common.interactors.d(jVar);
        io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.c;
        Intrinsics.checkNotNullExpressionValue(oVar, "io(...)");
        S6.c(oVar);
        return new com.quizlet.data.repository.activitycenter.b(dVar, oVar);
    }

    public final com.quizlet.data.interactor.set.c f0() {
        com.quizlet.data.repository.user.e userRepository = this.b.v1();
        androidx.work.impl.model.c dispatcher = u.v();
        AbstractC5040y ioDispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(userRepository, "userRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        com.quizlet.data.interactor.set.c cVar = new com.quizlet.data.interactor.set.c();
        cVar.a = userRepository;
        cVar.b = dispatcher;
        cVar.c = ioDispatcher;
        return cVar;
    }

    public final AutoLaunchEventLogger g() {
        return new AutoLaunchEventLogger((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.interactor.course.a g0() {
        return new com.quizlet.data.interactor.course.a((com.quizlet.infra.legacysyncengine.net.c) this.b.Q.get());
    }

    public final com.quizlet.data.repository.widget.b h() {
        return new com.quizlet.data.repository.widget.b(new com.quizlet.data.interactor.course.a((Braze) this.c.b.W0.get()), this.b.l0());
    }

    public final com.quizlet.quizletandroid.ui.group.data.b h0() {
        u uVar = this.b;
        return new com.quizlet.quizletandroid.ui.group.data.b(uVar.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get());
    }

    public final l1 i() {
        u uVar = this.b;
        long j = uVar.j();
        androidx.work.impl.model.c userProperties = uVar.m0();
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        return new l1(j, new com.quizlet.featuregate.features.folder.e(userProperties, 0));
    }

    public final androidx.compose.runtime.internal.j i0() {
        com.snowplowanalytics.core.tracker.o oVar;
        u uVar = this.b;
        io.ktor.client.plugins.api.d loginSignUpUserManager = uVar.t0();
        com.quizlet.login.common.interactors.d deepLinkRouter = uVar.t();
        com.google.android.gms.internal.appset.e logger = r0();
        com.quizlet.data.interactor.achievements.f isAnySubscriptionAvailableUseCase = new com.quizlet.data.interactor.achievements.f((com.quizlet.billing.subscriptions.i) uVar.u0.get());
        com.google.firebase.crashlytics.internal.settings.b requireEmailConfirmationFeature = uVar.a1();
        com.google.mlkit.vision.documentscanner.internal.c saveConfirmationWallEmailUseCase = new com.google.mlkit.vision.documentscanner.internal.c(new C4567d((InterfaceC1076h) uVar.C1.get(), 0));
        com.quizlet.data.repository.folderwithcreatorinclass.e qIncentivesUseCase = uVar.P0();
        androidx.work.impl.model.v onboardingQPlusUpsellUseCase = y0();
        com.snowplowanalytics.core.tracker.k serviceProvider = com.snowplowanalytics.snowplow.a.a;
        if (serviceProvider != null) {
            oVar = serviceProvider.e;
            if (oVar == null) {
                Intrinsics.checkNotNullParameter(serviceProvider, "serviceProvider");
                oVar = new com.snowplowanalytics.core.tracker.o(serviceProvider);
                serviceProvider.e = oVar;
            }
        } else {
            oVar = null;
        }
        com.quizlet.quizletandroid.ui.login.h loginSnowplowLogger = new com.quizlet.quizletandroid.ui.login.h(oVar, 11);
        com.google.firebase.crashlytics.internal.common.j onboardingELLUseCase = new com.google.firebase.crashlytics.internal.common.j(uVar.G0());
        Intrinsics.checkNotNullParameter(loginSignUpUserManager, "loginSignUpUserManager");
        Intrinsics.checkNotNullParameter(deepLinkRouter, "deepLinkRouter");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(isAnySubscriptionAvailableUseCase, "isAnySubscriptionAvailableUseCase");
        Intrinsics.checkNotNullParameter(requireEmailConfirmationFeature, "requireEmailConfirmationFeature");
        Intrinsics.checkNotNullParameter(saveConfirmationWallEmailUseCase, "saveConfirmationWallEmailUseCase");
        Intrinsics.checkNotNullParameter(qIncentivesUseCase, "qIncentivesUseCase");
        Intrinsics.checkNotNullParameter(onboardingQPlusUpsellUseCase, "onboardingQPlusUpsellUseCase");
        Intrinsics.checkNotNullParameter(loginSnowplowLogger, "loginSnowplowLogger");
        Intrinsics.checkNotNullParameter(onboardingELLUseCase, "onboardingELLUseCase");
        androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j();
        jVar.a = loginSignUpUserManager;
        jVar.b = deepLinkRouter;
        jVar.c = logger;
        jVar.d = isAnySubscriptionAvailableUseCase;
        jVar.e = requireEmailConfirmationFeature;
        jVar.f = saveConfirmationWallEmailUseCase;
        jVar.g = qIncentivesUseCase;
        jVar.h = onboardingQPlusUpsellUseCase;
        jVar.i = loginSnowplowLogger;
        jVar.j = onboardingELLUseCase;
        return jVar;
    }

    public final com.quizlet.quizletandroid.ui.setcreation.managers.b j() {
        return new com.quizlet.quizletandroid.ui.setcreation.managers.b(this.b.m0());
    }

    public final com.quizlet.features.home.logging.a j0() {
        return new com.quizlet.features.home.logging.a((EventLogger) this.b.l0.get());
    }

    public final androidx.work.impl.model.l k() {
        u uVar = this.b;
        com.quizlet.data.repository.activitycenter.b bVarK = uVar.k();
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) uVar.y0.get();
        return new androidx.work.impl.model.l(bVarK, AbstractC4178x.i(aVar, "growthBook", "learn_improvements_easier_1st_round", aVar));
    }

    public final com.quizlet.remote.model.notes.e k0() {
        u uVar = this.b;
        return new com.quizlet.remote.model.notes.e((com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get(), new J(uVar.j(), (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get()));
    }

    public final com.quizlet.local.ormlite.models.term.b l() {
        u uVar = this.b;
        return new com.quizlet.local.ormlite.models.term.b(new androidx.work.impl.model.c(new androidx.work.impl.model.c(uVar.m1(), u.v()), new com.quizlet.data.repository.folderwithcreator.e(new com.quizlet.data.repository.folderwithcreatorinclass.e(new androidx.work.impl.model.l(new androidx.work.impl.model.c(uVar.m(), uVar.M()), new com.quizlet.data.interactor.progress.c(new com.quizlet.login.common.interactors.d(uVar.f0()), new com.quizlet.quizletandroid.ui.folder.logging.a(1), u.V0(), new com.quizlet.quizletandroid.ui.activitycenter.models.a())), uVar.m(), uVar.M(), (com.quizlet.data.connectivity.a) uVar.X.get(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.folderwithcreatorinclass.e.class, "getLogger(...)")), uVar.H(), u.v())));
    }

    public final com.quizlet.learn.logging.a l0() {
        return new com.quizlet.learn.logging.a((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.repository.set.f m() {
        u uVar = this.b;
        com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
        Intrinsics.checkNotNullParameter(loader, "loader");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        return new com.quizlet.data.repository.set.f(loggedInUserManager.e.getPersonId(), loader);
    }

    public final LearnOnboardingEventLogger m0() {
        return new LearnOnboardingEventLogger((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.repository.folderwithcreatorinclass.e n() {
        u uVar = this.b;
        UserInfoCache userInfoCacheL0 = uVar.l0();
        IQuizletApiClient iQuizletApiClient = (IQuizletApiClient) uVar.O.get();
        com.quizlet.quizletandroid.managers.u uVarU0 = uVar.u0();
        com.quizlet.quizletandroid.util.d dVar = new com.quizlet.quizletandroid.util.d();
        com.quizlet.shared.usecase.folderstudymaterials.d dVar2 = new com.quizlet.shared.usecase.folderstudymaterials.d(26);
        Context context = uVar.a.a;
        S6.c(context);
        String RELEASE = Build.VERSION.RELEASE;
        Intrinsics.checkNotNullExpressionValue(RELEASE, "RELEASE");
        S6.c(RELEASE);
        return new com.quizlet.data.repository.folderwithcreatorinclass.e(userInfoCacheL0, iQuizletApiClient, uVarU0, dVar, dVar2, context, com.quizlet.featuregate.injection.a.d());
    }

    public final com.quizlet.data.repository.course.membership.c n0() {
        u uVar = this.b;
        androidx.work.impl.model.c userProps = uVar.m0();
        com.quizlet.data.repository.activitycenter.b eligibilityFeature = uVar.k();
        C4633r factory = (C4633r) uVar.T1.get();
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(eligibilityFeature, "eligibilityFeature");
        Intrinsics.checkNotNullParameter(factory, "factory");
        return new com.quizlet.data.repository.course.membership.c(new com.quizlet.data.repository.folderwithcreator.e(userProps, eligibilityFeature, factory));
    }

    public final com.quizlet.data.repository.activitycenter.b o() {
        u uVar = this.b;
        androidx.work.impl.model.c userProperties = uVar.m0();
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        return new com.quizlet.data.repository.activitycenter.b(new com.quizlet.featuregate.features.folder.b(userProperties, dispatcher), new com.quizlet.data.interactor.folder.f(uVar.G(), 0));
    }

    public final com.quizlet.learn.logging.d o0() {
        return new com.quizlet.learn.logging.d((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.interactor.course.a p() {
        u uVar = this.b;
        L l = (L) uVar.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.h.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.h hVar = (com.quizlet.remote.service.h) objL;
        S6.c(hVar);
        return new com.quizlet.data.interactor.course.a(new com.quizlet.data.repository.course.membership.c(new com.quizlet.quizletandroid.ui.setcreation.managers.n(hVar, new com.quizlet.quizletandroid.ui.onboarding.a(new com.quizlet.remote.model.school.a(), new com.quizlet.remote.model.course.c())), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.course.membership.c.class, "getLogger(...)"), com.quizlet.featuregate.injection.a.d()), u.v());
    }

    public final com.quizlet.library.logging.b p0() {
        return new com.quizlet.library.logging.b((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.repository.folderwithcreatorinclass.e q() {
        u uVar = this.b;
        return new com.quizlet.data.repository.folderwithcreatorinclass.e((com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), (EventLogger) uVar.l0.get(), (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get(), uVar.o());
    }

    public final io.ktor.client.plugins.api.d q0() {
        u uVar = this.b;
        IQuizletApiClient iQuizletApiClient = (IQuizletApiClient) uVar.O.get();
        ObjectReader objectReader = uVar.e();
        Intrinsics.checkNotNullParameter(objectReader, "objectReader");
        OneOffAPIParser oneOffAPIParser = new OneOffAPIParser();
        if (objectReader.getConfig().isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)) {
            timber.log.c.a(new RuntimeException("ObjectReader must not fail on unknown properties"));
        }
        oneOffAPIParser.a = objectReader;
        return new io.ktor.client.plugins.api.d(iQuizletApiClient, oneOffAPIParser, new ApiErrorResolverWrapper(uVar.q()));
    }

    public final com.quizlet.data.interactor.course.c r() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.course.c(uVar.U0(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.interactor.course.c.class, "getLogger(...)"), uVar.j());
    }

    public final com.google.android.gms.internal.appset.e r0() {
        u uVar = this.b;
        return new com.google.android.gms.internal.appset.e((EventLogger) uVar.l0.get(), uVar.O(), uVar.v0());
    }

    public final com.quizlet.data.interactor.school.b s() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.school.b(uVar.W0(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.interactor.school.b.class, "getLogger(...)"));
    }

    public final com.quizlet.features.infra.logout.viewmodels.d s0() {
        com.quizlet.quizletandroid.managers.u uVarU0 = this.b.u0();
        kotlinx.coroutines.scheduling.e eVar = O.a;
        S6.c(eVar);
        kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a;
        S6.c(dVar);
        return new com.quizlet.features.infra.logout.viewmodels.d(uVarU0, eVar, dVar);
    }

    public final DeepLinkEventLogger t() {
        return new DeepLinkEventLogger((EventLogger) this.b.l0.get());
    }

    public final com.quizlet.data.interactor.folderwithcreator.m t0() {
        u uVar = this.b;
        androidx.work.impl.model.c deleteFolderUseCase = new androidx.work.impl.model.c(uVar.G(), com.quizlet.featuregate.injection.a.d());
        com.quizlet.data.repository.qclass.c updateFolderUseCase = new com.quizlet.data.repository.qclass.c(uVar.G(), com.quizlet.featuregate.injection.a.d());
        com.quizlet.data.interactor.folder.c addSchoolCourseToFolderUseCase = new com.quizlet.data.interactor.folder.c(uVar.G(), com.quizlet.featuregate.injection.a.d(), 0);
        com.quizlet.data.repository.explanations.myexplanations.a removeSchoolCourseFromFolderUseCase = new com.quizlet.data.repository.explanations.myexplanations.a(uVar.G(), com.quizlet.featuregate.injection.a.d());
        com.quizlet.data.repository.course.membership.c coursePoweredFoldersFeature = uVar.r();
        Intrinsics.checkNotNullParameter(deleteFolderUseCase, "deleteFolderUseCase");
        Intrinsics.checkNotNullParameter(updateFolderUseCase, "updateFolderUseCase");
        Intrinsics.checkNotNullParameter(addSchoolCourseToFolderUseCase, "addSchoolCourseToFolderUseCase");
        Intrinsics.checkNotNullParameter(removeSchoolCourseFromFolderUseCase, "removeSchoolCourseFromFolderUseCase");
        Intrinsics.checkNotNullParameter(coursePoweredFoldersFeature, "coursePoweredFoldersFeature");
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.a = deleteFolderUseCase;
        mVar.b = updateFolderUseCase;
        mVar.c = addSchoolCourseToFolderUseCase;
        mVar.d = removeSchoolCourseFromFolderUseCase;
        mVar.e = coursePoweredFoldersFeature;
        return mVar;
    }

    public final Yh u() {
        u uVar = this.b;
        IQuizletApiClient iQuizletApiClient = (IQuizletApiClient) uVar.O.get();
        io.reactivex.rxjava3.core.o oVarL = com.quizlet.featuregate.injection.a.l();
        io.reactivex.rxjava3.core.o oVarJ = com.quizlet.featuregate.injection.a.j();
        com.quizlet.quizletandroid.config.b bVar = (com.quizlet.quizletandroid.config.b) uVar.M1.get();
        EventLogger eventLogger = (EventLogger) uVar.l0.get();
        com.quizlet.utmhelper.c cVar = (com.quizlet.utmhelper.c) this.D.get();
        com.quizlet.login.common.interactors.d dVarT = uVar.t();
        com.quizlet.quizletandroid.config.a aVar = (com.quizlet.quizletandroid.config.a) uVar.N1.get();
        com.quizlet.quizletandroid.config.c cVar2 = (com.quizlet.quizletandroid.config.c) uVar.L1.get();
        com.quizlet.quizletandroid.deeplinks.a base36Converter = com.quizlet.quizletandroid.deeplinks.a.a;
        Intrinsics.checkNotNullParameter(base36Converter, "base36Converter");
        return new Yh(iQuizletApiClient, oVarL, oVarJ, bVar, eventLogger, cVar, dVarT, aVar, cVar2, new com.quizlet.quizletandroid.deeplinks.a(), new com.quizlet.quizletandroid.deeplinks.a(), new com.quizlet.quizletandroid.deeplinks.a(), new com.quizlet.login.common.interactors.d((com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get()), new com.quizlet.quizletandroid.deeplinks.a(), uVar.c1, new com.quizlet.quizletandroid.managers.deeplinks.v());
    }

    public final V u0() {
        u uVar = this.b;
        return new V(uVar.l0(), new C0429a(uVar.j()), (com.quizlet.features.infra.basestudy.manager.a) this.c.j.get(), (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get(), new com.quizlet.features.match.highscore.b(uVar.q()), (IQuizletApiClient) uVar.O.get(), (DatabaseHelper) uVar.v.get(), com.quizlet.featuregate.injection.a.l());
    }

    public final com.quizlet.quizletandroid.managers.deeplinks.l v() {
        return new com.quizlet.quizletandroid.managers.deeplinks.l(com.quizlet.featuregate.injection.a.d(), (com.quizlet.quizletandroid.config.c) this.b.L1.get(), new com.quizlet.quizletandroid.managers.deeplinks.h());
    }

    public final com.quizlet.data.repository.studysetwithcreator.d v0() {
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) this.b.Z.get();
        com.quizlet.quizletandroid.deeplinks.a base36Converter = com.quizlet.quizletandroid.deeplinks.a.a;
        Intrinsics.checkNotNullParameter(base36Converter, "base36Converter");
        com.quizlet.quizletandroid.deeplinks.a setPageDeepLinkLookup = new com.quizlet.quizletandroid.deeplinks.a();
        V matchHighScoresDataManagerFactory = u0();
        com.quizlet.features.infra.basestudy.manager.a studyModeManagerFactory = (com.quizlet.features.infra.basestudy.manager.a) this.c.j.get();
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(setPageDeepLinkLookup, "setPageDeepLinkLookup");
        Intrinsics.checkNotNullParameter(matchHighScoresDataManagerFactory, "matchHighScoresDataManagerFactory");
        Intrinsics.checkNotNullParameter(studyModeManagerFactory, "studyModeManagerFactory");
        com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d();
        dVar.a = loggedInUserManager;
        dVar.b = setPageDeepLinkLookup;
        dVar.c = matchHighScoresDataManagerFactory;
        dVar.d = studyModeManagerFactory;
        return dVar;
    }

    public final com.quizlet.data.interactor.course.e w() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.course.e(uVar.U0(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.interactor.course.e.class, "getLogger(...)"), uVar.j());
    }

    public final com.quizlet.data.repository.course.membership.c w0() {
        com.quizlet.features.infra.basestudy.manager.a aVar = (com.quizlet.features.infra.basestudy.manager.a) this.c.j.get();
        u uVar = this.b;
        return new com.quizlet.data.repository.course.membership.c(aVar, new com.quizlet.features.match.logging.a((EventLogger) uVar.l0.get()), (EventLogger) uVar.l0.get());
    }

    public final com.quizlet.data.interactor.school.e x() {
        u uVar = this.b;
        return new com.quizlet.data.interactor.school.e(uVar.W0(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.interactor.school.e.class, "getLogger(...)"), uVar.j());
    }

    public final com.quizlet.features.notes.logging.f x0() {
        EventLogger eventLogger = (EventLogger) this.b.l0.get();
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        return new com.quizlet.features.notes.logging.f(eventLogger);
    }

    public final com.onetrust.otpublishers.headless.UI.fragment.q y() {
        return new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.remote.model.user.delete.c(this.b.n0(), com.quizlet.featuregate.injection.a.d()));
    }

    public final androidx.work.impl.model.v y0() {
        u uVar = this.b;
        Context context = uVar.q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = k0.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        com.quizlet.data.interactor.course.a aVar = new com.quizlet.data.interactor.course.a((InterfaceC1076h) k0.b.a(context, k0.a[0]));
        C4633r factory = (C4633r) uVar.R1.get();
        Intrinsics.checkNotNullParameter(factory, "factory");
        return new androidx.work.impl.model.v(aVar, factory.a("onboarding_ell_android", com.quizlet.featuregate.contracts.enums.c.a));
    }

    public final com.quizlet.data.repository.classfolder.e z() {
        u uVar = this.b;
        Context context = uVar.a.a;
        S6.c(context);
        return new com.quizlet.data.repository.classfolder.e(context, uVar.f(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.google.firebase.crashlytics.internal.common.j z0() {
        return new com.google.firebase.crashlytics.internal.common.j(new com.quizlet.remote.model.user.emailconfirmation.c(this.b.n0(), com.quizlet.featuregate.injection.a.d()));
    }
}
