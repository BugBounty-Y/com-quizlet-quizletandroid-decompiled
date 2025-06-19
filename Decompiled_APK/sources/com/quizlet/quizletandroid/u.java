package com.quizlet.quizletandroid;

import android.accounts.Account;
import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ShortcutManager;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.os.Looper;
import android.webkit.CookieManager;
import androidx.appcompat.widget.C0122z;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.ui.node.V;
import androidx.datastore.core.InterfaceC1076h;
import androidx.recyclerview.widget.C1372j;
import com.braze.Braze;
import com.comscore.streaming.ContentType;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.gtm.zzbu;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3502n4;
import com.google.android.gms.measurement.internal.J;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.di.ApiModule;
import com.quizlet.api.di.OkHttpModule;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.N1;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.qincentives.QIncentivesEventLogger;
import com.quizlet.generated.enums.I0;
import com.quizlet.infra.legacysyncengine.models.serializers.ApiThreeRequestSerializer;
import com.quizlet.local.datastore.preferences.AbstractC4568d0;
import com.quizlet.local.datastore.preferences.AbstractC4583t;
import com.quizlet.local.datastore.preferences.C4567d;
import com.quizlet.local.datastore.preferences.C4574j;
import com.quizlet.local.datastore.preferences.g0;
import com.quizlet.local.datastore.preferences.n0;
import com.quizlet.local.datastore.preferences.o0;
import com.quizlet.local.datastore.preferences.v0;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.dialogs.TextOverlayDialogFragment;
import com.quizlet.quizletandroid.ui.profile.UserFolderListFragment;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.remote.service.InterfaceC4774a;
import com.quizlet.remote.service.InterfaceC4775b;
import com.quizlet.remote.service.InterfaceC4776c;
import com.quizlet.remote.service.InterfaceC4777d;
import com.quizlet.remote.service.InterfaceC4779f;
import com.quizlet.remote.service.InterfaceC4780g;
import com.quizlet.uicommon.ui.common.dialogs.ConfirmationModalFragment;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalFragment;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class u extends H {
    public final dagger.hilt.android.internal.modules.a a;
    public final com.quizlet.shared.usecase.srs.a b;
    public final com.quizlet.shared.usecase.folderstudymaterials.c c;
    public final OkHttpModule d;
    public final ApiModule e;
    public final com.quizlet.shared.usecase.folderstudymaterials.a f;
    public final com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a g;
    public final com.quizlet.quizletandroid.injection.modules.a h;
    public final com.quizlet.shared.usecase.studiableMetadata.a i;
    public final com.quizlet.shared.usecase.folderstudymaterials.b j;
    public final com.quizlet.shared.usecase.folderstudymaterials.d k;
    public final com.google.firebase.heartbeatinfo.e l;
    public final com.google.mlkit.common.sdkinternal.b m;
    public final u n = this;
    public final dagger.internal.c o = AbstractC4178x.j(this, 0);
    public final dagger.internal.c p = dagger.internal.d.a(new t(this, 1));
    public final dagger.internal.c q = dagger.internal.d.a(new t(this, 2));
    public final dagger.internal.c r = AbstractC4178x.j(this, 3);
    public final dagger.internal.c s = AbstractC4178x.j(this, 4);
    public final dagger.internal.c t = dagger.internal.d.a(new t(this, 8));
    public final dagger.internal.c u = AbstractC4178x.j(this, 7);
    public final dagger.internal.c v = AbstractC4178x.j(this, 6);
    public final dagger.internal.c w = AbstractC4178x.j(this, 9);
    public final dagger.internal.c x = AbstractC4178x.j(this, 12);
    public final dagger.internal.c y = AbstractC4178x.j(this, 14);
    public final dagger.internal.c z = AbstractC4178x.j(this, 15);
    public final dagger.internal.c A = AbstractC4178x.j(this, 13);
    public final dagger.internal.c B = AbstractC4178x.j(this, 16);
    public final dagger.internal.c C = AbstractC4178x.j(this, 18);
    public final dagger.internal.c D = AbstractC4178x.j(this, 17);
    public final dagger.internal.c E = AbstractC4178x.j(this, 19);
    public final dagger.internal.c F = AbstractC4178x.j(this, 20);
    public final dagger.internal.c G = AbstractC4178x.j(this, 22);
    public final dagger.internal.c H = AbstractC4178x.j(this, 23);
    public final dagger.internal.c I = AbstractC4178x.j(this, 24);
    public final dagger.internal.c J = dagger.internal.d.a(new t(this, 26));
    public final dagger.internal.c K = AbstractC4178x.j(this, 25);
    public final dagger.internal.c L = AbstractC4178x.j(this, 28);
    public final dagger.internal.c M = AbstractC4178x.j(this, 27);
    public final dagger.internal.c N = dagger.internal.a.b(new t(this, 21));
    public final dagger.internal.c O = dagger.internal.d.a(new t(this, 29));
    public final dagger.internal.c P = dagger.internal.a.b(new t(this, 11));
    public final dagger.internal.c Q = dagger.internal.a.b(new t(this, 10));
    public final dagger.internal.c R = dagger.internal.a.b(new t(this, 32));
    public final dagger.internal.c S = dagger.internal.a.b(new t(this, 31));
    public final dagger.internal.c T = dagger.internal.a.b(new t(this, 33));
    public final dagger.internal.c U = dagger.internal.a.b(new t(this, 30));
    public final dagger.internal.c V = dagger.internal.d.a(new t(this, 34));
    public final dagger.internal.c W = dagger.internal.a.b(new t(this, 35));
    public final dagger.internal.c X = dagger.internal.a.b(new t(this, 36));
    public final dagger.internal.c Y = dagger.internal.d.a(new t(this, 37));
    public final dagger.internal.c Z = dagger.internal.a.b(new t(this, 5));
    public final dagger.internal.c a0 = dagger.internal.a.b(new t(this, 38));
    public final dagger.internal.c b0 = dagger.internal.a.b(new t(this, 41));
    public final dagger.internal.c c0 = dagger.internal.a.b(new t(this, 42));
    public final dagger.internal.c d0 = dagger.internal.a.b(new t(this, 40));
    public final dagger.internal.c e0 = dagger.internal.a.b(new t(this, 43));
    public final dagger.internal.c f0 = dagger.internal.a.b(new t(this, 39));
    public final dagger.internal.c g0 = dagger.internal.a.b(new t(this, 48));
    public final dagger.internal.c h0 = dagger.internal.a.b(new t(this, 49));
    public final dagger.internal.c i0 = dagger.internal.a.b(new t(this, 50));
    public final dagger.internal.c j0 = dagger.internal.a.b(new t(this, 51));
    public final dagger.internal.c k0 = dagger.internal.a.b(new t(this, 47));
    public final dagger.internal.c l0 = dagger.internal.a.b(new t(this, 46));
    public final dagger.internal.c m0 = dagger.internal.d.a(new t(this, 45));
    public final dagger.internal.c n0 = dagger.internal.d.a(new t(this, 52));
    public final dagger.internal.c o0 = AbstractC4178x.j(this, 44);
    public final dagger.internal.c p0 = AbstractC4178x.j(this, 54);
    public final dagger.internal.c q0 = AbstractC4178x.j(this, 53);
    public final dagger.internal.c r0 = AbstractC4178x.j(this, 57);
    public final dagger.internal.c s0 = AbstractC4178x.j(this, 56);
    public final dagger.internal.c t0 = AbstractC4178x.j(this, 58);
    public final dagger.internal.c u0 = AbstractC4178x.j(this, 55);
    public final t v0 = new t(this, 59);
    public final t w0 = new t(this, 61);
    public final t x0 = new t(this, 62);
    public final dagger.internal.c y0 = AbstractC4178x.j(this, 60);
    public final dagger.internal.c z0 = AbstractC4178x.j(this, 64);
    public final dagger.internal.c A0 = AbstractC4178x.j(this, 63);
    public final t B0 = new t(this, 65);
    public final t C0 = new t(this, 66);
    public final t D0 = new t(this, 67);
    public final t E0 = new t(this, 68);
    public final t F0 = new t(this, 69);
    public final t G0 = new t(this, 70);
    public final t H0 = new t(this, 71);
    public final dagger.internal.c I0 = AbstractC4178x.j(this, 73);
    public final dagger.internal.c J0 = dagger.internal.d.a(new t(this, 72));
    public final dagger.internal.c K0 = AbstractC4178x.j(this, 75);
    public final dagger.internal.c L0 = dagger.internal.d.a(new t(this, 74));
    public final dagger.internal.c M0 = dagger.internal.d.a(new t(this, 76));
    public final dagger.internal.c N0 = dagger.internal.a.b(new t(this, 78));
    public final dagger.internal.c O0 = dagger.internal.d.a(new t(this, 77));
    public final dagger.internal.c P0 = dagger.internal.d.a(new t(this, 79));
    public final t Q0 = new t(this, 81);
    public final dagger.internal.c R0 = dagger.internal.d.a(new t(this, 80));
    public final t S0 = new t(this, 83);
    public final t T0 = new t(this, 82);
    public final dagger.internal.c U0 = dagger.internal.d.a(new t(this, 84));
    public final dagger.internal.c V0 = dagger.internal.a.b(new t(this, 85));
    public final dagger.internal.c W0 = dagger.internal.d.a(new t(this, 88));
    public final dagger.internal.c X0 = dagger.internal.d.a(new t(this, 87));
    public final dagger.internal.c Y0 = dagger.internal.d.a(new t(this, 86));
    public final dagger.internal.c Z0 = dagger.internal.a.b(new t(this, 89));
    public final dagger.internal.c a1 = dagger.internal.a.b(new t(this, 90));
    public final dagger.internal.c b1 = dagger.internal.a.b(new t(this, 91));
    public final t c1 = new t(this, 92);
    public final dagger.internal.c d1 = dagger.internal.a.b(new t(this, 94));
    public final t e1 = new t(this, 93);
    public final dagger.internal.c f1 = dagger.internal.a.b(new t(this, 96));
    public final dagger.internal.c g1 = dagger.internal.d.a(new t(this, 97));
    public final dagger.internal.c h1 = dagger.internal.a.b(new t(this, 95));
    public final dagger.internal.c i1 = dagger.internal.a.b(new t(this, 98));
    public final dagger.internal.c j1 = AbstractC4178x.j(this, 99);
    public final dagger.internal.c k1 = AbstractC4178x.j(this, 101);
    public final t l1 = new t(this, 102);
    public final dagger.internal.c m1 = AbstractC4178x.j(this, 103);
    public final dagger.internal.c n1 = AbstractC4178x.j(this, 104);
    public final dagger.internal.c o1 = AbstractC4178x.j(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED);
    public final dagger.internal.c p1 = AbstractC4178x.j(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF);
    public final dagger.internal.c q1 = AbstractC4178x.j(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED);
    public final dagger.internal.c r1 = AbstractC4178x.j(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY);
    public final t s1 = new t(this, 100);
    public final t t1 = new t(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION);
    public final dagger.internal.c u1 = AbstractC4178x.j(this, OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED);
    public final dagger.internal.c v1 = AbstractC4178x.j(this, 111);
    public final dagger.internal.c w1 = AbstractC4178x.j(this, ContentType.LONG_FORM_ON_DEMAND);
    public final dagger.internal.c x1 = AbstractC4178x.j(this, 114);
    public final dagger.internal.c y1 = dagger.internal.d.a(new t(this, ContentType.LIVE));
    public final t z1 = new t(this, 115);
    public final t A1 = new t(this, 116);
    public final dagger.internal.c B1 = AbstractC4178x.j(this, 117);
    public final dagger.internal.c C1 = AbstractC4178x.j(this, 118);
    public final dagger.internal.c D1 = AbstractC4178x.j(this, 119);
    public final dagger.internal.c E1 = AbstractC4178x.j(this, 120);
    public final dagger.internal.c F1 = AbstractC4178x.j(this, ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND);
    public final dagger.internal.c G1 = AbstractC4178x.j(this, ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND);
    public final t H1 = new t(this, ContentType.USER_GENERATED_LIVE);
    public final dagger.internal.c I1 = dagger.internal.a.b(new t(this, 124));
    public final dagger.internal.c J1 = dagger.internal.a.b(new t(this, 125));
    public final dagger.internal.c K1 = dagger.internal.d.a(new t(this, 126));
    public final dagger.internal.c L1 = dagger.internal.a.b(new t(this, 127));
    public final dagger.internal.c M1 = dagger.internal.a.b(new t(this, 128));
    public final dagger.internal.c N1 = dagger.internal.a.b(new t(this, 129));
    public final dagger.internal.c O1 = dagger.internal.a.b(new t(this, 130));
    public final dagger.internal.c P1 = dagger.internal.a.b(new t(this, 131));
    public final dagger.internal.c Q1 = dagger.internal.d.a(new t(this, 132));
    public final dagger.internal.c R1 = dagger.internal.d.a(new t(this, 133));
    public final t S1 = new t(this, 134);
    public final dagger.internal.c T1 = dagger.internal.d.a(new t(this, 135));
    public final dagger.internal.c U1 = dagger.internal.a.b(new t(this, 137));
    public final dagger.internal.c V1 = dagger.internal.a.b(new t(this, 136));
    public final dagger.internal.c W1 = dagger.internal.d.a(new t(this, 138));
    public final dagger.internal.c X1 = dagger.internal.d.a(new t(this, 139));
    public final dagger.internal.c Y1 = dagger.internal.a.b(new t(this, ModuleDescriptor.MODULE_VERSION));
    public final dagger.internal.c Z1 = dagger.internal.a.b(new t(this, 140));
    public final dagger.internal.c a2 = dagger.internal.a.b(new t(this, 142));

    public u(ApiModule apiModule, com.onetrust.otpublishers.headless.Internal.Helper.h hVar, dagger.hilt.android.internal.modules.a aVar, com.quizlet.shared.usecase.folderstudymaterials.a aVar2, com.quizlet.shared.usecase.studiableMetadata.a aVar3, com.google.mlkit.common.sdkinternal.b bVar, com.quizlet.shared.usecase.folderstudymaterials.b bVar2, com.quizlet.shared.usecase.folderstudymaterials.c cVar, com.quizlet.quizletandroid.injection.modules.a aVar4, com.quizlet.shared.usecase.folderstudymaterials.d dVar, OkHttpModule okHttpModule, com.google.firebase.heartbeatinfo.e eVar, com.quizlet.shared.usecase.srs.a aVar5, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a aVar6, com.quizlet.shared.usecase.studiableMetadata.a aVar7, com.quizlet.quizletandroid.ui.login.di.a aVar8, retrofit2.adapter.rxjava3.d dVar2) {
        this.a = aVar;
        this.b = aVar5;
        this.c = cVar;
        this.d = okHttpModule;
        this.e = apiModule;
        this.f = aVar2;
        this.g = aVar6;
        this.h = aVar4;
        this.i = aVar3;
        this.j = bVar2;
        this.k = dVar;
        this.l = eVar;
        this.m = bVar;
    }

    public static com.quizlet.quizletandroid.ui.folder.logging.a V0() {
        return new com.quizlet.quizletandroid.ui.folder.logging.a(new com.quizlet.remote.model.school.a(), new com.quizlet.remote.model.course.c());
    }

    public static com.quizlet.data.repository.studysetwithcreatorinclass.g X0() {
        return new com.quizlet.data.repository.studysetwithcreatorinclass.g(new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(new com.quizlet.quizletandroid.ui.profile.p(1), new com.quizlet.quizletandroid.ui.common.images.capture.a(new com.quizlet.quizletandroid.ui.profile.p(1))), new com.quizlet.quizletandroid.ui.profile.data.b(3), V0(), new com.quizlet.quizletandroid.ui.profile.data.b(new com.quizlet.quizletandroid.ui.activitycenter.models.a()), new k(Y0()), new com.quizlet.data.repository.course.membership.c(new com.quizlet.quizletandroid.ui.common.images.capture.b(2), new k(Y0()), new com.quizlet.quizletandroid.ui.common.images.capture.a(new com.quizlet.quizletandroid.ui.profile.p(1))));
    }

    public static com.quizlet.data.repository.folderset.c Y0() {
        return new com.quizlet.data.repository.folderset.c(new com.quizlet.quizletandroid.ui.activitycenter.views.i(new com.quizlet.quizletandroid.ui.common.images.capture.b(2)), new C4636c(new com.quizlet.quizletandroid.ui.common.images.capture.b(2)), new com.quizlet.local.ormlite.models.term.b(new com.quizlet.quizletandroid.ui.common.images.capture.b(2)));
    }

    public static androidx.work.impl.model.c v() {
        com.google.mlkit.common.internal.model.a uiThread = new com.google.mlkit.common.internal.model.a(29);
        Intrinsics.checkNotNullParameter(uiThread, "uiThread");
        io.reactivex.rxjava3.core.o oVarA = io.reactivex.rxjava3.android.schedulers.b.a();
        Intrinsics.checkNotNullExpressionValue(oVarA, "mainThread(...)");
        io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.c;
        Intrinsics.checkNotNullExpressionValue(oVar, "io(...)");
        return new androidx.work.impl.model.c(oVarA, oVar);
    }

    public static com.onetrust.otpublishers.headless.UI.fragment.q y0() {
        com.quizlet.featuregate.features.flexiblegrading.a longTextFlexibleGradingExperiment = new com.quizlet.featuregate.features.flexiblegrading.a(2);
        Intrinsics.checkNotNullParameter(longTextFlexibleGradingExperiment, "longTextFlexibleGradingExperiment");
        return new com.onetrust.otpublishers.headless.UI.fragment.q(longTextFlexibleGradingExperiment);
    }

    public final androidx.work.impl.model.c A() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.l.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.l lVar = (com.quizlet.remote.service.l) objL;
        S6.c(lVar);
        return new androidx.work.impl.model.c(lVar, i0());
    }

    public final SharedPreferences A0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("quizlet_prefs", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return sharedPreferences;
    }

    public final com.quizlet.data.repository.searchexplanations.c B() {
        return new com.quizlet.data.repository.searchexplanations.c(new androidx.work.impl.model.v(A(), new com.quizlet.quizletandroid.ui.login.h(Y0()), new com.quizlet.quizletandroid.ui.folder.logging.a(3)), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.searchexplanations.c.class, "getLogger(...)"), com.quizlet.featuregate.injection.a.d());
    }

    public final SharedPreferences B0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("DeviceSharedPreferences", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return sharedPreferences;
    }

    public final com.quizlet.features.setpage.upsell.a C() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("ExplanationsUpsellPreferenceManager", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return new com.quizlet.features.setpage.upsell.a(sharedPreferences, 0);
    }

    public final com.quizlet.db.a C0() {
        SharedPreferences sharedPrefs = B0();
        Intrinsics.checkNotNullParameter(sharedPrefs, "sharedPrefs");
        return new com.quizlet.db.a(sharedPrefs, 1);
    }

    public final com.quizlet.data.interactor.achievements.f D() {
        Context context = this.a.a;
        S6.c(context);
        return new com.quizlet.data.interactor.achievements.f(new com.quizlet.facebook.b(context));
    }

    public final com.quizlet.data.repository.set.f D0() {
        Context contextQ = q();
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("PREFS_THEMES", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return new com.quizlet.data.repository.set.f(contextQ, sharedPreferences, (EventLogger) this.l0.get());
    }

    public final com.quizlet.data.repository.set.f E() {
        return new com.quizlet.data.repository.set.f(q(), new com.quizlet.quizletandroid.ui.common.images.capture.a(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.quizlet.remote.model.notes.e E0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.q.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.q qVar = (com.quizlet.remote.service.q) objL;
        S6.c(qVar);
        return new com.quizlet.remote.model.notes.e(qVar, com.quizlet.featuregate.injection.a.d(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.remote.model.notes.e.class, "getLogger(...)"), new com.quizlet.data.repository.widget.b(v1(), new k(14)), new k(14));
    }

    public final l1 F() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = AbstractC4583t.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        return new l1((InterfaceC1076h) AbstractC4583t.b.a(context, AbstractC4583t.a[0]), j());
    }

    public final com.facebook.z F0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("PREFS_OFFLINE_SETTINGS", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return new com.facebook.z(sharedPreferences, 1);
    }

    public final com.quizlet.data.repository.folder.i G() {
        com.quizlet.local.ormlite.models.bookmark.a aVar = new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.quizlet.local.ormlite.models.folder.a(1), new com.quizlet.local.ormlite.models.folder.a(2));
        com.quizlet.login.authentication.login.a aVar2 = new com.quizlet.login.authentication.login.a(h0());
        com.quizlet.quizletandroid.ui.folder.logging.a aVarV0 = V0();
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        androidx.work.impl.model.c cVar = new androidx.work.impl.model.c(aVar, new com.quizlet.remote.model.folder.p(aVar2, aVarV0, new com.quizlet.quizletandroid.ui.joincontenttofolder.i(2), new com.quizlet.remote.model.folder.course.a(new com.quizlet.remote.model.folder.course.b(), X0()), com.quizlet.featuregate.injection.a.d()));
        com.quizlet.data.connectivity.a aVar3 = (com.quizlet.data.connectivity.a) this.X.get();
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4780g.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4780g service = (InterfaceC4780g) objL;
        S6.c(service);
        com.quizlet.quizletandroid.ui.folder.logging.a folderMapper = V0();
        AbstractC5040y ioDispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        com.quizlet.data.interactor.set.c cVar2 = new com.quizlet.data.interactor.set.c();
        cVar2.a = service;
        cVar2.b = folderMapper;
        cVar2.c = ioDispatcher;
        return new com.quizlet.data.repository.folder.i(cVar, aVar3, cVar2, AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.folder.i.class, "getLogger(...)"));
    }

    public final com.lyft.android.scissors.b G0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = AbstractC4568d0.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        return new com.lyft.android.scissors.b((InterfaceC1076h) AbstractC4568d0.b.a(context, AbstractC4568d0.a[0]));
    }

    public final com.quizlet.data.repository.folderset.c H() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.n.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.n nVar = (com.quizlet.remote.service.n) objL;
        S6.c(nVar);
        return new com.quizlet.data.repository.folderset.c(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.explanations.myexplanations.a(new com.quizlet.quizletandroid.ui.setcreation.managers.n(nVar), new com.quizlet.quizletandroid.ui.joincontenttofolder.j(2))), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.folderset.c.class, "getLogger(...)"));
    }

    public final com.google.mlkit.vision.documentscanner.internal.c H0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = g0.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        return new com.google.mlkit.vision.documentscanner.internal.c((InterfaceC1076h) g0.b.a(context, g0.a[0]));
    }

    public final com.quizlet.data.repository.user.a I() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "folder_study_button_feature", aVar);
    }

    public final n0 I0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = o0.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        return new n0((InterfaceC1076h) o0.b.a(context, o0.a[0]));
    }

    public final com.quizlet.data.repository.user.a J() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "folder_study_learn_mode_feature", aVar);
    }

    public final androidx.work.impl.model.e J0() {
        q factory = (q) this.K1.get();
        Intrinsics.checkNotNullParameter(factory, "factory");
        return new androidx.work.impl.model.e(factory.a.a.k(), I0.PRACTICE_TESTS_CAN_UPLOAD_DOCUMENT);
    }

    public final com.quizlet.remote.model.folderstudymaterial.j K() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.o.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.o oVar = (com.quizlet.remote.service.o) objL;
        S6.c(oVar);
        return new com.quizlet.remote.model.folderstudymaterial.j(oVar, com.quizlet.featuregate.injection.a.d());
    }

    public final androidx.work.impl.model.e K0() {
        q factory = (q) this.K1.get();
        Intrinsics.checkNotNullParameter(factory, "factory");
        return new androidx.work.impl.model.e(factory.a.a.k(), I0.PRACTICE_TESTS_CAN_VIEW_TEST_PREVIEW_AND_TAKE_TEST);
    }

    public final com.quizlet.remote.model.folderstudymaterial.m L() {
        return new com.quizlet.remote.model.folderstudymaterial.m(K(), new com.quizlet.remote.model.folderstudymaterial.c(new com.quizlet.quizletandroid.ui.login.di.a(2), X0()), new com.quizlet.quizletandroid.ui.login.di.a(2), new com.quizlet.remote.model.base.b());
    }

    public final C3 L0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.r.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.r service = (com.quizlet.remote.service.r) objL;
        S6.c(service);
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        com.quizlet.quizletandroid.managers.upgrade.a questionBanksMapper = new com.quizlet.quizletandroid.managers.upgrade.a(3);
        androidx.compose.foundation.text.input.internal.u questionBankPreviewMapper = new androidx.compose.foundation.text.input.internal.u(new com.quizlet.quizletandroid.managers.upgrade.a(4), new com.quizlet.local.ormlite.models.term.b(new com.quizlet.quizletandroid.logging.initializer.a(3)), new com.quizlet.quizletandroid.ui.profile.b());
        com.quizlet.quizletandroid.ui.activitycenter.views.i practiceTestGradedQuestionMapper = new com.quizlet.quizletandroid.ui.activitycenter.views.i(new com.quizlet.quizletandroid.logging.initializer.a(3));
        com.quizlet.quizletandroid.ui.setcreation.adapters.a practiceTestConfigurationMapper = new com.quizlet.quizletandroid.ui.setcreation.adapters.a(2);
        com.quizlet.quizletandroid.ui.profile.b entitlementDataMapper = new com.quizlet.quizletandroid.ui.profile.b();
        Intrinsics.checkNotNullParameter(practiceTestGradedQuestionMapper, "practiceTestGradedQuestionMapper");
        Intrinsics.checkNotNullParameter(practiceTestConfigurationMapper, "practiceTestConfigurationMapper");
        Intrinsics.checkNotNullParameter(entitlementDataMapper, "entitlementDataMapper");
        com.quizlet.data.repository.login.a practiceTestResultMapper = new com.quizlet.data.repository.login.a();
        practiceTestResultMapper.a = practiceTestGradedQuestionMapper;
        practiceTestResultMapper.b = practiceTestConfigurationMapper;
        practiceTestResultMapper.c = entitlementDataMapper;
        com.quizlet.local.ormlite.models.term.b practiceTestsQuestionMapper = new com.quizlet.local.ormlite.models.term.b(new com.quizlet.quizletandroid.logging.initializer.a(3));
        com.quizlet.quizletandroid.ui.activitycenter.models.a remoteQuestionBankResultsMapper = new com.quizlet.quizletandroid.ui.activitycenter.models.a();
        com.quizlet.data.connectivity.a networkStatus = (com.quizlet.data.connectivity.a) this.X.get();
        C4636c questionCompatibilityHelper = new C4636c((com.squareup.moshi.l) this.V1.get());
        com.quizlet.quizletandroid.ui.setcreation.adapters.a practiceTestConfigurationMapper2 = new com.quizlet.quizletandroid.ui.setcreation.adapters.a(2);
        com.quizlet.quizletandroid.ui.profile.b entitlementDataMapper2 = new com.quizlet.quizletandroid.ui.profile.b();
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(questionBanksMapper, "questionBanksMapper");
        Intrinsics.checkNotNullParameter(questionBankPreviewMapper, "questionBankPreviewMapper");
        Intrinsics.checkNotNullParameter(practiceTestResultMapper, "practiceTestResultMapper");
        Intrinsics.checkNotNullParameter(practiceTestsQuestionMapper, "practiceTestsQuestionMapper");
        Intrinsics.checkNotNullParameter(remoteQuestionBankResultsMapper, "remoteQuestionBankResultsMapper");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(questionCompatibilityHelper, "questionCompatibilityHelper");
        Intrinsics.checkNotNullParameter(practiceTestConfigurationMapper2, "practiceTestConfigurationMapper");
        Intrinsics.checkNotNullParameter(entitlementDataMapper2, "entitlementDataMapper");
        C3 c3 = new C3();
        c3.a = service;
        c3.b = dispatcher;
        c3.c = questionBanksMapper;
        c3.d = questionBankPreviewMapper;
        c3.e = practiceTestResultMapper;
        c3.f = practiceTestsQuestionMapper;
        c3.g = remoteQuestionBankResultsMapper;
        c3.h = networkStatus;
        c3.i = questionCompatibilityHelper;
        c3.j = practiceTestConfigurationMapper2;
        c3.k = entitlementDataMapper2;
        return c3;
    }

    public final com.quizlet.local.ormlite.models.bookmark.a M() {
        return new com.quizlet.local.ormlite.models.bookmark.a(new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.quizlet.local.ormlite.models.folder.a(1), new com.quizlet.local.ormlite.models.folder.a(2)), u1(), new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.google.mlkit.common.sdkinternal.b(28)));
    }

    public final com.quizlet.data.repository.progress.b M0() {
        return new com.quizlet.data.repository.progress.b(O0(), N0(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.progress.b.class, "getLogger(...)"), (com.quizlet.data.connectivity.a) this.X.get());
    }

    public final com.quizlet.data.repository.folderwithcreator.e N() {
        com.quizlet.local.ormlite.models.bookmark.a aVarM = M();
        com.quizlet.remote.service.m mVarH0 = h0();
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4775b.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4775b interfaceC4775b = (InterfaceC4775b) objL;
        S6.c(interfaceC4775b);
        return new com.quizlet.data.repository.folderwithcreator.e(new androidx.work.impl.model.e(aVarM, new com.quizlet.remote.model.union.folderwithcreator.e(new com.quizlet.remote.model.union.folderwithcreator.b(mVarH0, interfaceC4775b), new com.quizlet.quizletandroid.ui.setcreation.managers.n(new com.quizlet.quizletandroid.ui.activitycenter.models.a(), V0()))), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.folderwithcreator.e.class, "getLogger(...)"));
    }

    public final com.quizlet.data.repository.folderwithcreator.e N0() {
        return new com.quizlet.data.repository.folderwithcreator.e(new com.google.firebase.crashlytics.internal.settings.b((DatabaseHelper) this.v.get()), (ModelIdentityProvider) this.B.get(), new com.quizlet.shared.usecase.folderstudymaterials.c(28));
    }

    public final com.quizlet.data.repository.user.a O() {
        com.google.android.gms.analytics.c cVar;
        com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        Application application = N6.b(this.a.a);
        S6.c(application);
        Intrinsics.checkNotNullParameter(application, "application");
        ArrayList arrayList = com.google.android.gms.analytics.a.g;
        com.google.android.gms.analytics.a googleAnalytics = zzbu.zzg(application).zzc();
        Intrinsics.checkNotNullExpressionValue(googleAnalytics, "getInstance(...)");
        S6.c(googleAnalytics);
        Intrinsics.checkNotNullParameter(googleAnalytics, "googleAnalytics");
        synchronized (googleAnalytics) {
            cVar = new com.google.android.gms.analytics.c((zzbu) googleAnalytics.c, "UA-41807927-1");
            cVar.zzW();
        }
        Intrinsics.checkNotNullExpressionValue(cVar, "newTracker(...)");
        return new com.quizlet.data.repository.user.a(dVar, cVar, (FirebaseAnalytics) this.U0.get());
    }

    public final com.quizlet.remote.model.progress.e O0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.s.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.s sVar = (com.quizlet.remote.service.s) objL;
        S6.c(sVar);
        return new com.quizlet.remote.model.progress.e(new com.quizlet.login.authentication.login.a(sVar), new com.quizlet.remote.model.progress.a());
    }

    public final k P() {
        return new k(new com.quizlet.quizletandroid.util.o(q()));
    }

    public final com.quizlet.data.repository.folderwithcreatorinclass.e P0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.t.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.t tVar = (com.quizlet.remote.service.t) objL;
        S6.c(tVar);
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(tVar, new com.quizlet.quizletandroid.managers.upgrade.a(4));
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        kotlin.reflect.n[] nVarArr = v0.a;
        Intrinsics.checkNotNullParameter(context, "<this>");
        return new com.quizlet.data.repository.folderwithcreatorinclass.e(cVar, new com.google.firebase.crashlytics.internal.settings.b((InterfaceC1076h) v0.b.a(context, v0.a[0])), new QIncentivesEventLogger((EventLogger) this.l0.get()), V(), com.quizlet.featuregate.injection.a.d());
    }

    public final kotlinx.coroutines.internal.d Q() {
        kotlinx.coroutines.scheduling.e dispatcher = O.a;
        S6.c(dispatcher);
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        return kotlinx.coroutines.E.c(dispatcher);
    }

    public final com.quizlet.quizletandroid.ui.base.g Q0() {
        return new com.quizlet.quizletandroid.ui.base.g((com.quizlet.quizletandroid.managers.audio.h) this.f0.get(), (com.squareup.otto.c) this.x.get(), new com.quizlet.baseui.managers.b(this.c1), (com.quizlet.quizletandroid.managers.c) this.i1.get(), (EventLogger) this.l0.get(), (FirebaseAnalytics) this.U0.get(), (com.google.firebase.crashlytics.b) this.t.get(), (com.quizlet.quizletandroid.managers.h) this.z0.get(), O(), (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get(), (com.quizlet.quizletandroid.ui.base.b) this.j1.get(), com.quizlet.featuregate.injection.a.j(), (com.quizlet.data.connectivity.a) this.X.get(), this.s1, this.t1, this.R0, (com.quizlet.usecase.a) this.u1.get(), Q(), new com.quizlet.features.notes.a((EventLogger) this.l0.get(), 2));
    }

    public final com.quizlet.data.repository.user.a R() {
        return new com.quizlet.data.repository.user.a(e0(), (com.quizlet.billing.subscriptions.i) this.u0.get(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.google.android.datatransport.cct.internal.s R0() {
        com.quizlet.local.ormlite.database.dao.b bookmarkDao = new com.quizlet.local.ormlite.database.dao.b((DatabaseHelper) this.v.get(), 0);
        com.google.android.material.floatingactionbutton.c folderDao = new com.google.android.material.floatingactionbutton.c((DatabaseHelper) this.v.get());
        com.lyft.android.scissors.b groupFolderDao = new com.lyft.android.scissors.b((DatabaseHelper) this.v.get());
        com.google.mlkit.vision.documentscanner.internal.c groupMembershipDao = new com.google.mlkit.vision.documentscanner.internal.c((DatabaseHelper) this.v.get());
        com.quizlet.data.interactor.course.a groupSetDao = new com.quizlet.data.interactor.course.a((DatabaseHelper) this.v.get());
        com.quizlet.data.interactor.achievements.f selectedTermDao = new com.quizlet.data.interactor.achievements.f((DatabaseHelper) this.v.get());
        com.onetrust.otpublishers.headless.UI.fragment.q studySetDao = new com.onetrust.otpublishers.headless.UI.fragment.q((DatabaseHelper) this.v.get());
        com.google.firebase.messaging.p termDao = new com.google.firebase.messaging.p((DatabaseHelper) this.v.get());
        com.quizlet.local.ormlite.database.dao.b userDao = new com.quizlet.local.ormlite.database.dao.b((DatabaseHelper) this.v.get(), 1);
        Intrinsics.checkNotNullParameter(bookmarkDao, "bookmarkDao");
        Intrinsics.checkNotNullParameter(folderDao, "folderDao");
        Intrinsics.checkNotNullParameter(groupFolderDao, "groupFolderDao");
        Intrinsics.checkNotNullParameter(groupMembershipDao, "groupMembershipDao");
        Intrinsics.checkNotNullParameter(groupSetDao, "groupSetDao");
        Intrinsics.checkNotNullParameter(selectedTermDao, "selectedTermDao");
        Intrinsics.checkNotNullParameter(studySetDao, "studySetDao");
        Intrinsics.checkNotNullParameter(termDao, "termDao");
        Intrinsics.checkNotNullParameter(userDao, "userDao");
        com.google.android.datatransport.cct.internal.s sVar = new com.google.android.datatransport.cct.internal.s();
        sVar.b = bookmarkDao;
        sVar.c = folderDao;
        sVar.d = groupFolderDao;
        sVar.e = groupMembershipDao;
        sVar.f = groupSetDao;
        sVar.g = selectedTermDao;
        sVar.a = studySetDao;
        sVar.h = termDao;
        sVar.i = userDao;
        return sVar;
    }

    public final com.quizlet.data.interactor.school.b S() {
        return new com.quizlet.data.interactor.school.b(new com.quizlet.data.repository.explanations.exercise.b(new com.quizlet.data.interactor.course.a(new androidx.work.impl.model.e(A(), new com.quizlet.data.repository.course.membership.c(new com.quizlet.quizletandroid.ui.common.images.capture.b(2), new k(Y0()), new com.quizlet.quizletandroid.ui.common.images.capture.a(new com.quizlet.quizletandroid.ui.profile.p(1))), new com.quizlet.quizletandroid.logging.initializer.a(2))), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.explanations.exercise.b.class, "getLogger(...)")), v());
    }

    public final com.quizlet.quizletandroid.ui.base.h S0() {
        return new com.quizlet.quizletandroid.ui.base.h(new com.quizlet.baseui.managers.b(this.c1), this.c1, O());
    }

    public final com.quizlet.data.interactor.folderstudymaterial.o T() {
        com.quizlet.remote.model.folderstudymaterial.m mVarL = L();
        InterfaceC1076h preferences = (InterfaceC1076h) this.q1.get();
        com.squareup.moshi.D moshi = (com.squareup.moshi.D) this.Q1.get();
        Intrinsics.checkNotNullParameter(preferences, "preferences");
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = com.squareup.moshi.H.f(List.class, N1.class);
        moshi.getClass();
        com.squareup.moshi.l lVarA = moshi.a(util$ParameterizedTypeImplF, com.squareup.moshi.internal.b.a, null);
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        return new com.quizlet.data.interactor.folderstudymaterial.o(mVarL, new androidx.work.impl.model.e(lVarA, preferences), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.interactor.folderstudymaterial.o.class, "getLogger(...)"));
    }

    public final com.quizlet.data.repository.set.f T0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.v.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.v vVar = (com.quizlet.remote.service.v) objL;
        S6.c(vVar);
        L l2 = (L) this.a1.get();
        Object objL2 = AbstractC4178x.l(l2, "retrofit", l2, "retrofit", com.quizlet.remote.service.u.class);
        Intrinsics.checkNotNullExpressionValue(objL2, "create(...)");
        com.quizlet.remote.service.u uVar = (com.quizlet.remote.service.u) objL2;
        S6.c(uVar);
        return new com.quizlet.data.repository.set.f(new com.google.firebase.messaging.p(new com.quizlet.remote.model.set.d(new com.quizlet.remote.model.set.a(vVar, uVar), new com.quizlet.remote.model.set.e(new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.profile.data.b(3), new com.quizlet.remote.model.school.a(), new com.quizlet.remote.model.course.c()), new com.quizlet.quizletandroid.ui.profile.b())), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.set.f.class, "getLogger(...)"));
    }

    public final com.quizlet.data.interactor.folderwithcreator.m U() {
        com.quizlet.data.repository.folderwithcreator.e repository = N();
        androidx.work.impl.model.c dispatcher = v();
        AbstractC5040y ioDispatcher = com.quizlet.featuregate.injection.a.d();
        androidx.work.impl.model.c getBookmarkedFoldersForUserUseCase = new androidx.work.impl.model.c(N(), com.quizlet.featuregate.injection.a.d());
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.interactor.folderwithcreator.m.class, "getLogger(...)");
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(getBookmarkedFoldersForUserUseCase, "getBookmarkedFoldersForUserUseCase");
        Intrinsics.checkNotNullParameter(logger, "logger");
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.a = repository;
        mVar.b = dispatcher;
        mVar.c = ioDispatcher;
        mVar.d = getBookmarkedFoldersForUserUseCase;
        mVar.e = logger;
        return mVar;
    }

    public final androidx.work.impl.model.n U0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.i.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.i iVar = (com.quizlet.remote.service.i) objL;
        S6.c(iVar);
        return new androidx.work.impl.model.n(iVar, new com.quizlet.remote.model.course.c(), V0(), com.quizlet.featuregate.injection.a.d());
    }

    public final kotlinx.coroutines.internal.d V() {
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        return kotlinx.coroutines.E.c(dispatcher);
    }

    public final com.quizlet.quizletandroid.util.f W() {
        Context context = q();
        com.quizlet.partskit.widgets.icon.b iconProvider = new com.quizlet.partskit.widgets.icon.b(q());
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(iconProvider, "iconProvider");
        return new com.quizlet.quizletandroid.util.f(context, iconProvider);
    }

    public final com.quizlet.data.repository.set.f W0() {
        return new com.quizlet.data.repository.set.f(j0(), new com.quizlet.remote.model.school.a(), com.quizlet.featuregate.injection.a.d());
    }

    public final com.quizlet.quizletandroid.interactor.p X() {
        return new com.quizlet.quizletandroid.interactor.p(new com.google.firebase.crashlytics.internal.common.j((InterfaceC1076h) this.o1.get()), new com.google.firebase.crashlytics.internal.settings.b(k()), new androidx.work.impl.model.v(K0(), (com.quizlet.data.connectivity.a) this.X.get()));
    }

    public final com.quizlet.data.interactor.widget.a Y() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.F.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.F service = (com.quizlet.remote.service.F) objL;
        S6.c(service);
        com.quizlet.remote.model.widget.a mapper = new com.quizlet.remote.model.widget.a();
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        UserInfoCache userInfo = l0();
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.widget.b.class, "getLogger(...)");
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(userInfo, "userInfo");
        Intrinsics.checkNotNullParameter(logger, "logger");
        C1608n c1608n = new C1608n();
        c1608n.a = service;
        c1608n.b = mapper;
        c1608n.c = dispatcher;
        c1608n.d = userInfo;
        c1608n.e = logger;
        return new com.quizlet.data.interactor.widget.a(new com.quizlet.data.repository.widget.b(c1608n, (com.quizlet.local.cache.caches.c) this.N0.get()));
    }

    public final com.quizlet.db.a Z() {
        SharedPreferences sharedPreferences = A0();
        com.quizlet.db.token.a accessTokenProvider = (com.quizlet.db.token.a) this.u.get();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        return new com.quizlet.db.a(sharedPreferences, 0);
    }

    public final V Z0() {
        ModelIdentityProvider modelIdentityProvider = (ModelIdentityProvider) this.B.get();
        com.quizlet.infra.legacysyncengine.net.listeners.d responseDispatcher = (com.quizlet.infra.legacysyncengine.net.listeners.d) this.D.get();
        ExecutionRouter executionRouter = (ExecutionRouter) this.w.get();
        ObjectReader objectReader = e();
        ExecutionRouter executionRouter2 = (ExecutionRouter) this.w.get();
        Intrinsics.checkNotNullParameter(objectReader, "objectReader");
        Intrinsics.checkNotNullParameter(executionRouter2, "executionRouter");
        androidx.work.impl.model.c apiThreeParser = new androidx.work.impl.model.c(22, objectReader, executionRouter2.b());
        com.quizlet.infra.legacysyncengine.tasks.parse.f responseHandler = (com.quizlet.infra.legacysyncengine.tasks.parse.f) this.F.get();
        com.google.android.datatransport.cct.internal.s taskFactory = s1();
        com.squareup.otto.c bus = (com.squareup.otto.c) this.x.get();
        DatabaseHelper database = (DatabaseHelper) this.v.get();
        IQuizletApiClient quizletApiClient = (IQuizletApiClient) this.O.get();
        com.quizlet.db.a globalSharedPreferencesManager = Z();
        UserInfoCache userInfoCache = l0();
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(responseDispatcher, "responseDispatcher");
        Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
        Intrinsics.checkNotNullParameter(apiThreeParser, "apiThreeParser");
        Intrinsics.checkNotNullParameter(responseHandler, "responseHandler");
        Intrinsics.checkNotNullParameter(taskFactory, "taskFactory");
        Intrinsics.checkNotNullParameter(bus, "bus");
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(globalSharedPreferencesManager, "globalSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        return new V(modelIdentityProvider, responseDispatcher, executionRouter, apiThreeParser, responseHandler, taskFactory, bus, database, quizletApiClient);
    }

    public final String a0() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        String string = context.getString(R.string.google_server_client_id);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        S6.c(string);
        return string;
    }

    public final com.google.firebase.crashlytics.internal.settings.b a1() {
        androidx.work.impl.model.c userProperties = m0();
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        return new com.google.firebase.crashlytics.internal.settings.b(userProperties);
    }

    public final com.quizlet.data.repository.achievements.h b() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4774a.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4774a interfaceC4774a = (InterfaceC4774a) objL;
        S6.c(interfaceC4774a);
        com.google.android.gms.internal.appset.e remote = new com.google.android.gms.internal.appset.e(interfaceC4774a, new com.quizlet.remote.model.achievements.d(), com.quizlet.featuregate.injection.a.d());
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.achievements.h.class, "getLogger(...)");
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        com.quizlet.local.cache.caches.a achievementsCache = (com.quizlet.local.cache.caches.a) this.k1.get();
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(achievementsCache, "achievementsCache");
        com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h();
        hVar.a = remote;
        hVar.b = logger;
        hVar.c = dispatcher;
        hVar.d = achievementsCache;
        return hVar;
    }

    public final com.quizlet.data.repository.user.a b0() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "2025_bts_mobile_home_feed_use_new_service", aVar);
    }

    public final com.google.firebase.crashlytics.internal.common.j b1() {
        return new com.google.firebase.crashlytics.internal.common.j(new com.google.firebase.crashlytics.internal.common.j((InterfaceC1076h) this.o1.get()));
    }

    public final com.quizlet.ads.d c() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("AD_UNIT_SHARED_PREF", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return new com.quizlet.ads.d(sharedPreferences, j());
    }

    public final com.quizlet.data.repository.user.a c0() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "2025_bts_mobile_home_feed_show_progress", aVar);
    }

    public final com.google.android.gms.internal.appset.e c1() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        return new com.google.android.gms.internal.appset.e(new com.quizlet.scandocument.ui.d(context), m0(), new com.google.mlkit.common.internal.model.a(26));
    }

    public final androidx.compose.material.ripple.r d() {
        com.google.firebase.messaging.p getFolderToAddMaterialUseCase = new com.google.firebase.messaging.p(new com.google.firebase.crashlytics.internal.common.j(new com.quizlet.data.repository.searchexplanations.c(K(), new com.quizlet.remote.model.foldertoadd.b())));
        com.onetrust.otpublishers.headless.UI.fragment.q manipulateFolderSelected = new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.interactor.folderstudymaterial.z(new com.google.firebase.crashlytics.internal.settings.b(new com.onetrust.otpublishers.headless.UI.fragment.q(new com.quizlet.data.repository.qclass.c(K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.quizlet.data.interactor.achievements.f(new com.google.firebase.messaging.p(new com.quizlet.data.repository.qclass.c(K(), new com.quizlet.quizletandroid.ui.login.di.a(2)))), new com.google.firebase.perf.logging.b(24)));
        J createFolderUseCase = new J(G(), U0(), j(), com.quizlet.featuregate.injection.a.d());
        Intrinsics.checkNotNullParameter(getFolderToAddMaterialUseCase, "getFolderToAddMaterialUseCase");
        Intrinsics.checkNotNullParameter(manipulateFolderSelected, "manipulateFolderSelected");
        Intrinsics.checkNotNullParameter(createFolderUseCase, "createFolderUseCase");
        androidx.compose.material.ripple.r rVar = new androidx.compose.material.ripple.r();
        rVar.b = getFolderToAddMaterialUseCase;
        rVar.c = manipulateFolderSelected;
        rVar.e = createFolderUseCase;
        rVar.d = new ArrayList();
        return rVar;
    }

    public final com.quizlet.features.emailconfirmation.logging.a d0() {
        EventLogger eventLogger = (EventLogger) this.l0.get();
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        return new com.quizlet.features.emailconfirmation.logging.a(eventLogger, 3);
    }

    public final com.facebook.z d1() {
        SharedPreferences sharedPreferences = A0();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        return new com.facebook.z(sharedPreferences, 2);
    }

    public final ObjectReader e() {
        ObjectMapper objectMapper = (ObjectMapper) this.E.get();
        Intrinsics.checkNotNullParameter(objectMapper, "objectMapper");
        ObjectReader objectReader = objectMapper.readerFor(objectMapper.getTypeFactory().constructParametricType(ApiThreeWrapper.class, DataWrapper.class));
        Intrinsics.checkNotNullExpressionValue(objectReader, "readerFor(...)");
        S6.c(objectReader);
        return objectReader;
    }

    public final com.lyft.android.scissors.b e0() {
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        return new com.lyft.android.scissors.b(loggedInUserManager);
    }

    public final androidx.work.impl.model.n e1() {
        return new androidx.work.impl.model.n(com.quizlet.featuregate.injection.a.d(), new com.quizlet.data.repository.user.a(m1(), o(), (com.quizlet.cache.a) this.g1.get()), l0(), (com.quizlet.infra.legacysyncengine.net.c) this.Q.get());
    }

    public final ObjectWriter f() {
        ObjectMapper objectMapper = (ObjectMapper) this.E.get();
        Intrinsics.checkNotNullParameter(objectMapper, "objectMapper");
        ObjectWriter objectWriterWriter = objectMapper.writer();
        Intrinsics.checkNotNullExpressionValue(objectWriterWriter, "writer(...)");
        S6.c(objectWriterWriter);
        return objectWriterWriter;
    }

    public final InterfaceC4776c f0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4776c.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4776c interfaceC4776c = (InterfaceC4776c) objL;
        S6.c(interfaceC4776c);
        return interfaceC4776c;
    }

    public final androidx.work.impl.model.l f1() {
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        com.quizlet.generated.enums.H h = com.quizlet.generated.enums.H.UNITED_STATES;
        com.quizlet.featuregate.features.region.a aVar = com.quizlet.featuregate.features.region.a.a;
        return new androidx.work.impl.model.l(new com.quizlet.data.repository.login.a(dispatcher, h, 4), m0());
    }

    public final io.ktor.client.plugins.api.d g() {
        Context context = q();
        com.quizlet.quizletandroid.util.f languageUtil = (com.quizlet.quizletandroid.util.f) this.a0.get();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(languageUtil, "languageUtil");
        return new io.ktor.client.plugins.api.d(context, languageUtil);
    }

    public final com.quizlet.data.repository.set.f g0() {
        com.quizlet.infra.contracts.growthbook.a growthBook = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        androidx.work.impl.model.c userProps = m0();
        C4633r factory = (C4633r) this.X1.get();
        Intrinsics.checkNotNullParameter(growthBook, "growthBook");
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(factory, "factory");
        return new com.quizlet.data.repository.set.f(userProps, new com.quizlet.data.repository.user.a("mx_es_alternate_study_mode_names", growthBook), factory.a("br_pt_alternate_learn_study_mode_names", com.quizlet.featuregate.contracts.enums.a.a));
    }

    public final com.quizlet.data.repository.login.a g1() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.A.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.A a = (com.quizlet.remote.service.A) objL;
        S6.c(a);
        com.quizlet.quizletandroid.ui.login.h remoteDataStore = new com.quizlet.quizletandroid.ui.login.h(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(a), new com.quizlet.quizletandroid.ui.onboarding.a(2));
        com.quizlet.data.connectivity.a networkStatus = (com.quizlet.data.connectivity.a) this.X.get();
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.login.a.class, "getLogger(...)");
        Intrinsics.checkNotNullParameter(remoteDataStore, "remoteDataStore");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        aVar.a = remoteDataStore;
        aVar.b = networkStatus;
        aVar.c = logger;
        return aVar;
    }

    public final okhttp3.s h() {
        com.google.mlkit.common.sdkinternal.model.a apiUrlProvider = new com.google.mlkit.common.sdkinternal.model.a(29);
        Intrinsics.checkNotNullParameter(apiUrlProvider, "apiUrlProvider");
        try {
            Intrinsics.checkNotNullParameter("https://api.quizlet.com/3.11/", "<this>");
            C1372j c1372j = new C1372j();
            c1372j.l(null, "https://api.quizlet.com/3.11/");
            return c1372j.d();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public final com.quizlet.remote.service.m h0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.m.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.m mVar = (com.quizlet.remote.service.m) objL;
        S6.c(mVar);
        return mVar;
    }

    public final com.features.flashcards.creatormarketing.h h1() {
        return new com.features.flashcards.creatormarketing.h((EventLogger) this.l0.get(), 2);
    }

    public final com.quizlet.login.common.interactors.d i() {
        return new com.quizlet.login.common.interactors.d((Braze) this.W0.get());
    }

    public final com.quizlet.remote.service.p i0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.p.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.p pVar = (com.quizlet.remote.service.p) objL;
        S6.c(pVar);
        return pVar;
    }

    public final com.quizlet.features.infra.ui.feedback.sound.soundeffect.e i1() {
        Context context = this.a.a;
        S6.c(context);
        com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e(context, (AudioAttributes) this.p.get(), (AudioManager) this.q.get());
        com.google.android.material.floatingactionbutton.c cVar = new com.google.android.material.floatingactionbutton.c(new com.quizlet.local.datastore.models.metering.i((InterfaceC1076h) this.r.get(), 1));
        kotlinx.coroutines.scheduling.e eVar2 = O.a;
        S6.c(eVar2);
        return new com.quizlet.features.infra.ui.feedback.sound.soundeffect.e(eVar, cVar, eVar2);
    }

    public final long j() {
        UserInfoCache userInfoCache = l0();
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        return userInfoCache.getPersonId();
    }

    public final com.quizlet.remote.service.x j0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.x.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.x xVar = (com.quizlet.remote.service.x) objL;
        S6.c(xVar);
        return xVar;
    }

    public final com.quizlet.billing.register.a j1() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.quizlet.quizletandroid.modes", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        return new com.quizlet.billing.register.a(sharedPreferences, 1);
    }

    public final com.quizlet.data.repository.activitycenter.b k() {
        return new com.quizlet.data.repository.activitycenter.b(p(), l0());
    }

    public final com.quizlet.remote.service.y k0() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.y.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.y yVar = (com.quizlet.remote.service.y) objL;
        S6.c(yVar);
        return yVar;
    }

    public final com.quizlet.quizletandroid.ui.setcreation.managers.p k1() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        return new com.quizlet.quizletandroid.ui.setcreation.managers.p(context);
    }

    public final com.quizlet.features.notes.a l() {
        return new com.quizlet.features.notes.a((EventLogger) this.l0.get(), 1);
    }

    public final UserInfoCache l0() {
        SharedPreferences sharedPreferences = A0();
        com.quizlet.db.token.a accessTokenProvider = (com.quizlet.db.token.a) this.u.get();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
        return new UserInfoCache(sharedPreferences, accessTokenProvider);
    }

    public final com.quizlet.data.repository.studysetwithcreator.d l1() {
        com.quizlet.local.ormlite.models.studysetwithcreator.a aVarN1 = n1();
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.B.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.B b = (com.quizlet.remote.service.B) objL;
        S6.c(b);
        androidx.work.impl.model.v factory = new androidx.work.impl.model.v(aVarN1, new com.quizlet.remote.model.union.studysetwithcreator.c(new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(b), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.profile.data.b(3), new com.quizlet.quizletandroid.ui.folder.logging.a(3), new com.quizlet.quizletandroid.ui.profile.p(3), new com.quizlet.quizletandroid.ui.joincontenttofolder.j(3)));
        com.quizlet.data.connectivity.a networkStatus = (com.quizlet.data.connectivity.a) this.X.get();
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.studysetwithcreator.d.class, "getLogger(...)");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d();
        dVar.a = factory;
        dVar.b = networkStatus;
        dVar.c = dispatcher;
        dVar.d = logger;
        return dVar;
    }

    public final com.quizlet.local.ormlite.models.bookmark.a m() {
        return new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.onetrust.otpublishers.headless.Internal.Helper.h(28));
    }

    public final androidx.work.impl.model.c m0() {
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        com.quizlet.billing.subscriptions.i subscriptionLookup = (com.quizlet.billing.subscriptions.i) this.u0.get();
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(subscriptionLookup, "subscriptionLookup");
        return new androidx.work.impl.model.c(loggedInUserManager, subscriptionLookup);
    }

    public final com.quizlet.data.repository.studysetwithcreatorinclass.g m1() {
        com.quizlet.data.repository.activitycenter.b bVar = new com.quizlet.data.repository.activitycenter.b(new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.quizlet.shared.usecase.folderstudymaterials.b(28)), n1());
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4779f.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4779f interfaceC4779f = (InterfaceC4779f) objL;
        S6.c(interfaceC4779f);
        return new com.quizlet.data.repository.studysetwithcreatorinclass.g(new com.quizlet.data.interactor.school.b(bVar, new com.quizlet.remote.model.union.studysetwithcreatorinclass.e(new com.quizlet.quizletandroid.ui.login.h(interfaceC4779f), new com.quizlet.quizletandroid.ui.joincontenttofolder.j(1), new com.quizlet.quizletandroid.ui.profile.data.b(3), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), com.quizlet.featuregate.injection.a.d())), new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.quizlet.shared.usecase.folderstudymaterials.b(28)), n1(), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.studysetwithcreatorinclass.g.class, "getLogger(...)"));
    }

    public final com.quizlet.data.repository.classfolder.e n() {
        return new com.quizlet.data.repository.classfolder.e(new com.quizlet.data.repository.explanations.myexplanations.a(m(), new com.quizlet.data.repository.widget.b(new com.quizlet.login.authentication.login.a(f0()), new com.quizlet.quizletandroid.ui.folder.logging.a(1))), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.classfolder.e.class, "getLogger(...)"));
    }

    public final com.quizlet.remote.service.E n0() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.E.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.E e = (com.quizlet.remote.service.E) objL;
        S6.c(e);
        return e;
    }

    public final com.quizlet.local.ormlite.models.studysetwithcreator.a n1() {
        return new com.quizlet.local.ormlite.models.studysetwithcreator.a(new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new com.quizlet.local.ormlite.models.set.a()), u1());
    }

    public final com.quizlet.data.repository.classmembership.c o() {
        L l = (L) this.W.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", InterfaceC4777d.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        InterfaceC4777d interfaceC4777d = (InterfaceC4777d) objL;
        S6.c(interfaceC4777d);
        return new com.quizlet.data.repository.classmembership.c(new androidx.compose.foundation.text.input.internal.u(interfaceC4777d, new com.quizlet.quizletandroid.ui.joincontenttofolder.i(1)), new com.quizlet.data.repository.activitycenter.b(R0(), new com.quizlet.shared.usecase.folderstudymaterials.a(28)), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.classmembership.c.class, "getLogger(...)"), (com.quizlet.data.connectivity.a) this.X.get());
    }

    public final com.quizlet.ads.b o0() {
        return new com.quizlet.ads.b(m0(), c(), y());
    }

    public final com.quizlet.features.infra.studysetting.managers.a o1() {
        com.quizlet.infra.legacysyncengine.net.f syncDispatcher = (com.quizlet.infra.legacysyncengine.net.f) this.U.get();
        UserInfoCache userInfoCache = l0();
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        return new com.quizlet.features.infra.studysetting.managers.a(syncDispatcher, userInfoCache.getPersonId());
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, kotlin.k] */
    public final com.quizlet.data.repository.user.eligibility.g p() {
        com.quizlet.data.interactor.achievements.f fVar = new com.quizlet.data.interactor.achievements.f((com.quizlet.local.cache.caches.b) this.n1.get());
        com.quizlet.shared.usecase.eligibility.c cVar = (com.quizlet.shared.usecase.eligibility.c) com.quizlet.shared.usecase.di.b.b.getValue();
        S6.c(cVar);
        return new com.quizlet.data.repository.user.eligibility.g(fVar, new com.quizlet.data.repository.searchexplanations.c(cVar, com.quizlet.featuregate.injection.a.d()), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.user.eligibility.g.class, "getLogger(...)"), Q());
    }

    public final com.quizlet.features.emailconfirmation.logging.a p0() {
        return new com.quizlet.features.emailconfirmation.logging.a((EventLogger) this.l0.get(), 2);
    }

    public final com.quizlet.data.repository.user.a p1() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "SubfolderFeatureFlag", aVar);
    }

    public final Context q() {
        Application application = N6.b(this.a.a);
        S6.c(application);
        Intrinsics.checkNotNullParameter(application, "application");
        Context applicationContext = application.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        S6.c(applicationContext);
        return applicationContext;
    }

    public final com.quizlet.data.repository.user.a q0() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "learn_checkpoint_settings", aVar);
    }

    public final com.quizlet.billing.subscriptions.h q1() {
        IQuizletApiClient quizletApiClient = (IQuizletApiClient) this.O.get();
        io.reactivex.rxjava3.core.o networkScheduler = com.quizlet.featuregate.injection.a.l();
        io.reactivex.rxjava3.core.o mainThredScheduler = com.quizlet.featuregate.injection.a.j();
        com.quizlet.features.emailconfirmation.logging.a eventLogger = d0();
        Intrinsics.checkNotNullParameter(quizletApiClient, "quizletApiClient");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainThredScheduler, "mainThredScheduler");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h(quizletApiClient, networkScheduler, mainThredScheduler, eventLogger);
        com.lyft.android.scissors.b bVarE0 = e0();
        com.quizlet.billing.manager.f fVar = (com.quizlet.billing.manager.f) this.s0.get();
        com.quizlet.billing.subscriptions.i iVar = (com.quizlet.billing.subscriptions.i) this.u0.get();
        com.quizlet.billing.manager.sku.a skuResolver = (com.quizlet.billing.manager.sku.a) this.t0.get();
        Intrinsics.checkNotNullParameter(skuResolver, "skuResolver");
        com.google.android.material.floatingactionbutton.c cVar = new com.google.android.material.floatingactionbutton.c(skuResolver);
        SharedPreferences sharedPreferences = A0();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        return new com.quizlet.billing.subscriptions.h(hVar, bVarE0, fVar, iVar, cVar, new com.quizlet.billing.register.a(sharedPreferences, 0), v0());
    }

    public final com.quizlet.data.repository.course.membership.c r() {
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        AbstractC5040y dispatcher2 = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(dispatcher2, "dispatcher");
        com.quizlet.data.repository.login.a usConstrainedFeature = new com.quizlet.data.repository.login.a(dispatcher2, com.quizlet.generated.enums.H.UNITED_STATES, 12);
        androidx.work.impl.model.c userProperties = m0();
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(usConstrainedFeature, "usConstrainedFeature");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        return new com.quizlet.data.repository.course.membership.c(dispatcher, usConstrainedFeature, userProperties);
    }

    public final com.quizlet.data.repository.user.a r0() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "learn_settings_refresh", aVar);
    }

    public final com.quizlet.data.interactor.achievements.f r1() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("SYNCED_ACTIVITY_CENTER_SHARED_PREF", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        S6.c(sharedPreferences);
        return new com.quizlet.data.interactor.achievements.f(new com.quizlet.quizletandroid.ui.activitycenter.managers.b(sharedPreferences));
    }

    public final com.quizlet.data.repository.user.a s() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "creator_retention_bottomsheet_redesign_android", aVar);
    }

    public final com.quizlet.data.repository.user.a s0() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "LibraryRedesignFeatureFlag", aVar);
    }

    public final com.google.android.datatransport.cct.internal.s s1() {
        DatabaseHelper database = (DatabaseHelper) this.v.get();
        ModelIdentityProvider modelIdentityProvider = (ModelIdentityProvider) this.B.get();
        com.quizlet.infra.legacysyncengine.net.listeners.d responseDispatcher = (com.quizlet.infra.legacysyncengine.net.listeners.d) this.D.get();
        ExecutionRouter executionRouter = (ExecutionRouter) this.w.get();
        ObjectReader objectReader = e();
        ObjectWriter objectWriter = f();
        Intrinsics.checkNotNullParameter(objectWriter, "objectWriter");
        ApiThreeRequestSerializer serializer = new ApiThreeRequestSerializer(objectWriter);
        com.quizlet.db.a globalSharedPreferencesManager = Z();
        io.reactivex.rxjava3.core.o parseScheduler = com.quizlet.featuregate.injection.a.k();
        io.reactivex.rxjava3.core.o mainThreadScheduler = com.quizlet.featuregate.injection.a.j();
        ObjectReader objectReader2 = e();
        ObjectWriter objectWriter2 = f();
        okhttp3.s baseUrl = h();
        Intrinsics.checkNotNullParameter(globalSharedPreferencesManager, "globalSharedPreferencesManager");
        Intrinsics.checkNotNullParameter(parseScheduler, "parseScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(objectReader2, "objectReader");
        Intrinsics.checkNotNullParameter(objectWriter2, "objectWriter");
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        com.onetrust.otpublishers.headless.UI.fragment.q requestFactory = new com.onetrust.otpublishers.headless.UI.fragment.q(objectReader2, baseUrl);
        okhttp3.A okHttpClient = (okhttp3.A) this.N.get();
        ModelIdentityProvider modelIdentityProvider2 = (ModelIdentityProvider) this.B.get();
        RelationshipGraph relationshipGraph = (RelationshipGraph) this.y.get();
        Intrinsics.checkNotNullParameter(modelIdentityProvider2, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(relationshipGraph, "relationshipGraph");
        androidx.compose.foundation.text.input.internal.u modelResolver = new androidx.compose.foundation.text.input.internal.u(modelIdentityProvider2, false, relationshipGraph, 20);
        RelationshipGraph relationshipGraph2 = (RelationshipGraph) this.y.get();
        com.quizlet.infra.legacysyncengine.net.listeners.d dispatcher = (com.quizlet.infra.legacysyncengine.net.listeners.d) this.D.get();
        Intrinsics.checkNotNullParameter(database, "database");
        Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
        Intrinsics.checkNotNullParameter(responseDispatcher, "responseDispatcher");
        Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
        Intrinsics.checkNotNullParameter(objectReader, "objectReader");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(requestFactory, "requestFactory");
        Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
        Intrinsics.checkNotNullParameter(modelResolver, "modelResolver");
        Intrinsics.checkNotNullParameter(relationshipGraph2, "relationshipGraph");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        com.google.android.datatransport.cct.internal.s sVar = new com.google.android.datatransport.cct.internal.s();
        if (objectReader.getConfig().isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)) {
            timber.log.c.a(new IllegalStateException("ObjectReader must not fail on unknown properties"));
        }
        sVar.b = database;
        sVar.c = modelIdentityProvider;
        sVar.d = responseDispatcher;
        sVar.e = executionRouter;
        sVar.g = serializer;
        sVar.a = requestFactory;
        sVar.h = okHttpClient;
        sVar.f = modelResolver;
        sVar.i = relationshipGraph2;
        return sVar;
    }

    public final com.quizlet.login.common.interactors.d t() {
        SharedPreferences sharedPreferences = A0();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        com.quizlet.db.b upgradeTargetManager = new com.quizlet.db.b(sharedPreferences, 0);
        Intrinsics.checkNotNullParameter(upgradeTargetManager, "upgradeTargetManager");
        return new com.quizlet.login.common.interactors.d(upgradeTargetManager);
    }

    public final io.ktor.client.plugins.api.d t0() {
        com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        com.quizlet.braze.e eVar = (com.quizlet.braze.e) this.X0.get();
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        com.quizlet.braze.e brazeUserManager = (com.quizlet.braze.e) this.X0.get();
        com.quizlet.infra.legacysyncengine.net.f syncDispatcher = (com.quizlet.infra.legacysyncengine.net.f) this.U.get();
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(brazeUserManager, "brazeUserManager");
        Intrinsics.checkNotNullParameter(syncDispatcher, "syncDispatcher");
        return new io.ktor.client.plugins.api.d(dVar, eVar, new com.quizlet.data.repository.set.f(loggedInUserManager, brazeUserManager, syncDispatcher));
    }

    public final com.quizlet.remote.model.notes.e t1() {
        L l = (L) this.a1.get();
        Object objL = AbstractC4178x.l(l, "retrofit", l, "retrofit", com.quizlet.remote.service.D.class);
        Intrinsics.checkNotNullExpressionValue(objL, "create(...)");
        com.quizlet.remote.service.D d = (com.quizlet.remote.service.D) objL;
        S6.c(d);
        return new com.quizlet.remote.model.notes.e(d, com.quizlet.featuregate.injection.a.d(), (com.quizlet.data.connectivity.a) this.X.get(), new com.quizlet.quizletandroid.logging.initializer.a(new com.quizlet.quizletandroid.ui.joincontenttofolder.j(1), new com.quizlet.quizletandroid.ui.profile.data.b(3), new com.quizlet.quizletandroid.ui.onboarding.a(3), new com.quizlet.quizletandroid.ui.activitycenter.models.a()), new C4636c((com.squareup.moshi.l) this.V1.get()));
    }

    public final androidx.work.impl.model.e u() {
        return new androidx.work.impl.model.e(G(), com.quizlet.featuregate.injection.a.d());
    }

    /* JADX WARN: Type inference failed for: r3v14, types: [java.lang.Object, kotlin.k] */
    public final com.quizlet.quizletandroid.managers.u u0() {
        com.quizlet.infra.legacysyncengine.managers.d dVar = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        DatabaseHelper databaseHelper = (DatabaseHelper) this.v.get();
        com.quizlet.data.repository.set.f fVarD0 = D0();
        com.quizlet.local.cache.caches.a aVar = (com.quizlet.local.cache.caches.a) this.k1.get();
        com.quizlet.quizletandroid.managers.audio.h hVar = (com.quizlet.quizletandroid.managers.audio.h) this.f0.get();
        com.quizlet.billing.subscriptions.h hVarQ1 = q1();
        com.google.android.gms.internal.appset.e eVarC1 = c1();
        com.quizlet.data.repository.classfolder.e eVarV0 = v0();
        t tVar = this.l1;
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        com.google.android.gms.internal.p000authapi.b bVarC = AbstractC3441d3.c(context);
        Intrinsics.checkNotNullExpressionValue(bVarC, "getSignInClient(...)");
        Context context2 = q();
        Context context3 = q();
        Intrinsics.checkNotNullParameter(context3, "context");
        String clientId = context3.getString(R.string.google_client_id);
        Intrinsics.checkNotNullExpressionValue(clientId, "getString(...)");
        S6.c(clientId);
        Intrinsics.checkNotNullParameter(clientId, "clientId");
        GoogleSignInOptions googleSignInOptions = GoogleSignInOptions.k;
        new HashSet();
        new HashMap();
        com.google.android.gms.common.internal.u.h(googleSignInOptions);
        HashSet hashSet = new HashSet(googleSignInOptions.b);
        String str = googleSignInOptions.g;
        Account account = googleSignInOptions.c;
        String str2 = googleSignInOptions.h;
        HashMap mapB = GoogleSignInOptions.b(googleSignInOptions.i);
        String str3 = googleSignInOptions.j;
        hashSet.add(GoogleSignInOptions.l);
        hashSet.add(GoogleSignInOptions.m);
        com.google.android.gms.common.internal.u.e(clientId);
        com.google.android.gms.common.internal.u.a("two different server client ids provided", str == null || str.equals(clientId));
        if (hashSet.contains(GoogleSignInOptions.p)) {
            Scope scope = GoogleSignInOptions.o;
            if (hashSet.contains(scope)) {
                hashSet.remove(scope);
            }
        }
        if (account == null || !hashSet.isEmpty()) {
            hashSet.add(GoogleSignInOptions.n);
        }
        GoogleSignInOptions googleSignInOptions2 = new GoogleSignInOptions(3, new ArrayList(hashSet), account, true, googleSignInOptions.e, googleSignInOptions.f, clientId, str2, mapB, str3);
        Intrinsics.checkNotNullExpressionValue(googleSignInOptions2, "build(...)");
        Intrinsics.checkNotNullParameter(context2, "context");
        Intrinsics.checkNotNullParameter(googleSignInOptions2, "googleSignInOptions");
        com.google.android.gms.auth.api.signin.a aVar2 = new com.google.android.gms.auth.api.signin.a(context2, null, com.google.android.gms.auth.api.a.a, googleSignInOptions2, new com.google.android.gms.common.api.d(new com.google.mlkit.common.sdkinternal.model.a(9), Looper.getMainLooper()));
        Intrinsics.checkNotNullExpressionValue(aVar2, "getClient(...)");
        com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(bVarC, aVar2);
        Context context4 = q();
        Intrinsics.checkNotNullParameter(context4, "context");
        Intrinsics.checkNotNullParameter(context4, "context");
        com.google.android.material.floatingactionbutton.c cVar = new com.google.android.material.floatingactionbutton.c(new androidx.credentials.f(context4));
        Context context5 = q();
        Intrinsics.checkNotNullParameter(context5, "context");
        Object systemService = context5.getSystemService("shortcut");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.content.pm.ShortcutManager");
        ShortcutManager shortcutManager = (ShortcutManager) systemService;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        S6.c(eVar);
        AbstractC5040y abstractC5040yD = com.quizlet.featuregate.injection.a.d();
        com.google.android.material.floatingactionbutton.c cVar2 = new com.google.android.material.floatingactionbutton.c((InterfaceC1076h) this.m1.get());
        com.quizlet.usecase.b bVar2 = (com.quizlet.usecase.b) this.o.get();
        com.google.firebase.messaging.p pVar = new com.google.firebase.messaging.p(p());
        com.quizlet.shared.usecase.session.b bVar3 = (com.quizlet.shared.usecase.session.b) com.quizlet.shared.usecase.di.f.g.getValue();
        S6.c(bVar3);
        com.google.firebase.crashlytics.internal.common.j jVar = new com.google.firebase.crashlytics.internal.common.j((InterfaceC1076h) this.o1.get());
        C4567d c4567d = new C4567d((InterfaceC1076h) this.p1.get(), 1);
        C4574j c4574j = new C4574j((InterfaceC1076h) this.q1.get(), 1);
        Context context6 = this.a.a;
        S6.c(context6);
        return new com.quizlet.quizletandroid.managers.u(dVar, databaseHelper, fVarD0, aVar, hVar, hVarQ1, eVarC1, eVarV0, tVar, bVar, cVar, shortcutManager, eVar, abstractC5040yD, cVar2, bVar2, pVar, bVar3, jVar, c4567d, c4574j, context6, D(), (CookieManager) this.r1.get());
    }

    public final com.quizlet.local.ormlite.models.bookmark.a u1() {
        return new com.quizlet.local.ormlite.models.bookmark.a(R0(), (ModelIdentityProvider) this.B.get(), new assistantMode.utils.studiableMetadata.b(29));
    }

    public final com.quizlet.data.repository.classfolder.e v0() {
        return new com.quizlet.data.repository.classfolder.e(m0(), new com.quizlet.analytics.marketing.appsflyer.e(q()));
    }

    public final com.quizlet.data.repository.user.e v1() {
        return new com.quizlet.data.repository.user.e(new com.quizlet.data.repository.explanations.myexplanations.a(u1(), new com.quizlet.data.repository.course.membership.c(new com.quizlet.quizletandroid.ui.activitycenter.views.i(n0()), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.folder.logging.a(3))), (com.quizlet.data.connectivity.a) this.X.get(), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.user.e.class, "getLogger(...)"), com.quizlet.featuregate.injection.a.d());
    }

    public final C4636c w() {
        AbstractC3502n4.i(6, "expectedSize");
        C0122z c0122z = new C0122z(6);
        c0122z.u(InfoModalFragment.class, this.B0);
        c0122z.u(ConfirmationModalFragment.class, this.C0);
        c0122z.u(ImageOverlayDialogFragment.class, this.D0);
        c0122z.u(TextOverlayDialogFragment.class, this.E0);
        c0122z.u(UserFolderListFragment.class, this.F0);
        c0122z.u(UserSetListFragment.class, this.G0);
        return new C4636c(c0122z.h());
    }

    public final com.quizlet.data.repository.metering.j w0() {
        com.quizlet.data.repository.folderwithcreator.e remote = new com.quizlet.data.repository.folderwithcreator.e(i0(), new com.quizlet.quizletandroid.ui.profile.p(2), com.quizlet.featuregate.injection.a.d());
        com.quizlet.data.repository.folderset.c local = new com.quizlet.data.repository.folderset.c(new com.quizlet.local.datastore.models.metering.i((InterfaceC1076h) this.K0.get(), 0), new com.quizlet.local.datastore.models.metering.j(), com.quizlet.featuregate.injection.a.d());
        org.slf4j.b logger = AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.metering.j.class, "getLogger(...)");
        AbstractC5040y dispatcher = com.quizlet.featuregate.injection.a.d();
        Intrinsics.checkNotNullParameter(remote, "remote");
        Intrinsics.checkNotNullParameter(local, "local");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
        jVar.a = remote;
        jVar.b = local;
        jVar.c = logger;
        jVar.d = dispatcher;
        return jVar;
    }

    public final com.quizlet.data.repository.explanations.myexplanations.a w1() {
        Context context = this.a.a;
        S6.c(context);
        return new com.quizlet.data.repository.explanations.myexplanations.a(context, (FolderLogger) this.J1.get());
    }

    public final com.quizlet.quizletandroid.ui.setcreation.managers.i x() {
        DBUser dBUser;
        com.quizlet.infra.legacysyncengine.datasources.d editSetDataSourceFactory = new com.quizlet.infra.legacysyncengine.datasources.d((com.quizlet.infra.legacysyncengine.net.c) this.Q.get(), 1);
        com.quizlet.infra.legacysyncengine.managers.i saveManager = (com.quizlet.infra.legacysyncengine.managers.i) this.S.get();
        com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a studySetChangeState = (com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a) this.F1.get();
        com.quizlet.quizletandroid.ui.setcreation.managers.p studySetLastEditTracker = k1();
        SharedPreferences sharedPreferences = A0();
        Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
        com.quizlet.db.b editSetLanguageCache = new com.quizlet.db.b(sharedPreferences, 1);
        ExecutionRouter executionRouter = (ExecutionRouter) this.w.get();
        UserInfoCache userInfoCache = l0();
        com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) this.Z.get();
        Intrinsics.checkNotNullParameter(editSetDataSourceFactory, "editSetDataSourceFactory");
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(studySetChangeState, "studySetChangeState");
        Intrinsics.checkNotNullParameter(studySetLastEditTracker, "studySetLastEditTracker");
        Intrinsics.checkNotNullParameter(editSetLanguageCache, "editSetLanguageCache");
        Intrinsics.checkNotNullParameter(executionRouter, "executionRouter");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        return new com.quizlet.quizletandroid.ui.setcreation.managers.i(editSetDataSourceFactory, saveManager, studySetChangeState, studySetLastEditTracker, editSetLanguageCache, executionRouter, userInfoCache.getPersonId(), (loggedInUserManager == null || (dBUser = loggedInUserManager.r) == null || (dBUser.getIsUnderAge() && !loggedInUserManager.r.getIsConfirmed())) ? false : true);
    }

    public final com.quizlet.data.repository.explanations.myexplanations.a x0() {
        return new com.quizlet.data.repository.explanations.myexplanations.a(new C1721Kc(A(), new com.quizlet.quizletandroid.ui.activitycenter.models.a(), new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(2), new com.quizlet.quizletandroid.managers.upgrade.a(2), new com.quizlet.quizletandroid.ui.common.adapter.c()), AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.repository.explanations.myexplanations.a.class, "getLogger(...)"));
    }

    public final androidx.work.impl.r x1() {
        Context context = q();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.work.impl.r rVarH = androidx.work.impl.r.h(context);
        Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
        S6.c(rVarH);
        return rVarH;
    }

    public final com.quizlet.data.repository.user.a y() {
        com.quizlet.infra.contracts.growthbook.a aVar = (com.quizlet.infra.contracts.growthbook.a) this.y0.get();
        return AbstractC4178x.i(aVar, "growthBook", "enable_prebid_sdk_ads_solution", aVar);
    }

    public final J z() {
        return new J(new com.quizlet.data.interactor.school.b(C(), m0()), C(), new com.onetrust.otpublishers.headless.UI.fragment.q((EventLogger) this.l0.get()), j());
    }

    public final org.slf4j.b z0() {
        return AbstractC4178x.o((org.slf4j.a) this.Y.get(), "loggerFactory", com.quizlet.data.interactor.metering.b.class, "getLogger(...)");
    }
}
