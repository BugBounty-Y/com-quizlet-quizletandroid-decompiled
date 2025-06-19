package com.quizlet.quizletandroid;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Handler;
import android.webkit.CookieManager;
import androidx.compose.ui.node.V;
import androidx.datastore.core.InterfaceC1076h;
import com.amazon.device.ads.DTBAdNetwork;
import com.amazon.device.ads.DTBAdNetworkInfo;
import com.amazon.device.ads.DTBAdRequest;
import com.appsflyer.attribution.RequestError;
import com.braze.Braze;
import com.comscore.android.util.AndroidTcfDataLoader;
import com.comscore.streaming.ContentType;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.measurement.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N5;
import com.google.firebase.analytics.FirebaseAnalytics;
import com.google.firebase.messaging.FirebaseMessaging;
import com.j256.ormlite.android.apptools.OpenHelperManager;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTUXParams;
import com.onetrust.otpublishers.headless.Public.OTBannerHeightRatio;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.perimeterx.mobile_sdk.main.PXInterceptor;
import com.quizlet.api.IHttpErrorManager;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.QuizletApiClient;
import com.quizlet.api.cookie.QuizletCookieManager;
import com.quizlet.api.di.ApiModule;
import com.quizlet.api.di.OkHttpModule;
import com.quizlet.api.di.OkHttpModule_ProvideOkHttpClient$api_releaseFactory;
import com.quizlet.api.di.QuizletApiClientHelperFactoryModule_ProvideConverterFactoryFactory;
import com.quizlet.api.okhttp.interceptors.AcceptLanguageInterceptor;
import com.quizlet.api.okhttp.interceptors.AppSessionIdProvider;
import com.quizlet.api.okhttp.interceptors.AppSessionInterceptor;
import com.quizlet.api.okhttp.interceptors.AuthorizationInterceptor;
import com.quizlet.api.okhttp.interceptors.DeviceIdInterceptor;
import com.quizlet.api.okhttp.interceptors.ReleaseBuildFlavorInterceptorProvider;
import com.quizlet.api.okhttp.interceptors.SecurityChallengeInterceptor;
import com.quizlet.api.okhttp.interceptors.UserAgentInterceptor;
import com.quizlet.api.util.TaggedSocketFactory;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.model.BasicCourseFolder;
import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderStudyMaterial;
import com.quizlet.data.model.DeletedFolderStudyMaterial;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.FullCourseFolder;
import com.quizlet.data.model.M1;
import com.quizlet.data.model.N1;
import com.quizlet.data.model.RecommendedStudyMaterial;
import com.quizlet.data.model.Section;
import com.quizlet.data.model.StudyMaterialItem$ExplanationQuestionItem;
import com.quizlet.data.model.StudyMaterialItem$FlashcardSetItem;
import com.quizlet.data.model.StudyMaterialItem$FolderItem;
import com.quizlet.data.model.StudyMaterialItem$NoteItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookExerciseItem;
import com.quizlet.data.model.StudyMaterialItem$TextbookItem;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.database.DbSizeHelper;
import com.quizlet.db.data.models.base.RelationshipGraph;
import com.quizlet.db.data.models.identity.ModelIdentityProvider;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.db.data.net.localid.LocalIdMap;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.EventFileWriter;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.EventLogCounter;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.experimentation.ExperimentEnrollmentLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.eventlogger.interceptor.EventLogInterceptorManager;
import com.quizlet.eventlogger.model.HashMapEventLog;
import com.quizlet.infra.legacysyncengine.models.identity.ModelKeyFieldChangeMapper;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import com.quizlet.local.datastore.preferences.AbstractC4569e;
import com.quizlet.local.datastore.preferences.C4589z;
import com.quizlet.local.datastore.preferences.D0;
import com.quizlet.local.datastore.preferences.J;
import com.quizlet.local.datastore.preferences.K;
import com.quizlet.local.datastore.preferences.O;
import com.quizlet.local.datastore.preferences.Q;
import com.quizlet.local.datastore.preferences.z0;
import com.quizlet.login.LoginNavActivity;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.ads.C4641h;
import com.quizlet.quizletandroid.ui.search.SearchActivity;
import com.quizlet.remote.model.practicetests.QuestionCompatibility;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import java.io.File;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.Timer;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.SocketFactory;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.e0;
import org.json.JSONObject;
import retrofit2.C5184i;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class t implements dagger.internal.c {
    public final u a;
    public final int b;

    public t(u uVar, int i) {
        this.a = uVar;
        this.b = i;
    }

    /* JADX WARN: Type inference failed for: r0v240, types: [java.lang.Object, kotlin.k] */
    public final Object a() throws IllegalAccessException, SecurityException, IllegalArgumentException {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        u uVar = this.a;
        int i = this.b;
        switch (i) {
            case 0:
                return new com.quizlet.usecase.a(1, kotlinx.coroutines.channels.a.b);
            case 1:
                AudioAttributes audioAttributesBuild = new AudioAttributes.Builder().setContentType(4).setUsage(1).build();
                Intrinsics.checkNotNullExpressionValue(audioAttributesBuild, "build(...)");
                S6.c(audioAttributesBuild);
                return audioAttributesBuild;
            case 2:
                Context context = uVar.a.a;
                S6.c(context);
                Intrinsics.checkNotNullParameter(context, "context");
                Object systemService = context.getSystemService("audio");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.media.AudioManager");
                return (AudioManager) systemService;
            case 3:
                Context context2 = uVar.q();
                Intrinsics.checkNotNullParameter(context2, "context");
                kotlin.reflect.n[] nVarArr = z0.a;
                Intrinsics.checkNotNullParameter(context2, "<this>");
                return (InterfaceC1076h) z0.b.a(context2, z0.a[0]);
            case 4:
                return new com.quizlet.quizletandroid.ui.common.images.loading.glide.a();
            case 5:
                DatabaseHelper databaseHelper = (DatabaseHelper) uVar.v.get();
                ExecutionRouter executionRouter = (ExecutionRouter) uVar.w.get();
                SharedPreferences sharedPreferences = uVar.A0();
                Intrinsics.checkNotNullParameter(sharedPreferences, "sharedPreferences");
                com.quizlet.features.setpage.upsell.a aVar = new com.quizlet.features.setpage.upsell.a(sharedPreferences, 1);
                UserInfoCache userInfoCacheL0 = uVar.l0();
                com.quizlet.db.token.a aVar2 = (com.quizlet.db.token.a) uVar.u.get();
                com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                com.quizlet.infra.legacysyncengine.net.f fVar = (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get();
                IQuizletApiClient iQuizletApiClient = (IQuizletApiClient) uVar.O.get();
                io.reactivex.rxjava3.core.o oVarL = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o oVarJ = com.quizlet.featuregate.injection.a.j();
                com.squareup.otto.c cVar2 = (com.squareup.otto.c) uVar.x.get();
                FirebaseMessaging firebaseMessaging = (FirebaseMessaging) uVar.V.get();
                io.reactivex.rxjava3.core.o scheduler = io.reactivex.rxjava3.schedulers.e.c;
                Intrinsics.checkNotNullExpressionValue(scheduler, "io(...)");
                S6.c(scheduler);
                Intrinsics.checkNotNullParameter(firebaseMessaging, "firebaseMessaging");
                Intrinsics.checkNotNullParameter(scheduler, "scheduler");
                return new com.quizlet.infra.legacysyncengine.managers.d(databaseHelper, executionRouter, aVar, userInfoCacheL0, aVar2, cVar, fVar, iQuizletApiClient, oVarL, oVarJ, cVar2, new com.quizlet.data.repository.widget.b(firebaseMessaging, scheduler), new com.quizlet.infra.legacysyncengine.managers.g(uVar.q()), new com.quizlet.data.interactor.school.b(new com.quizlet.data.repository.user.a(new com.quizlet.data.repository.activitycenter.b(new com.quizlet.data.repository.user.a(uVar.R0(), (ModelIdentityProvider) uVar.B.get(), new retrofit2.adapter.rxjava3.d(28)), new com.quizlet.remote.model.user.a(uVar.n0(), new com.quizlet.quizletandroid.managers.upgrade.a(4))), (com.quizlet.data.connectivity.a) uVar.X.get(), AbstractC4178x.o((org.slf4j.a) uVar.Y.get(), "loggerFactory", com.quizlet.data.repository.user.a.class, "getLogger(...)")), u.v()), new retrofit2.adapter.rxjava3.d(28));
            case 6:
                Context context3 = uVar.q();
                UserInfoCache userInfoCache = uVar.l0();
                Intrinsics.checkNotNullParameter(context3, "context");
                Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
                DatabaseHelper databaseHelper2 = (DatabaseHelper) OpenHelperManager.getHelper(context3, DatabaseHelper.class);
                databaseHelper2.setUserId(Long.valueOf(userInfoCache.getPersonId()));
                return databaseHelper2;
            case 7:
                SharedPreferences sharedPreferences2 = uVar.A0();
                com.google.firebase.crashlytics.b firebaseCrashlytics = (com.google.firebase.crashlytics.b) uVar.t.get();
                Intrinsics.checkNotNullParameter(sharedPreferences2, "sharedPreferences");
                Intrinsics.checkNotNullParameter(firebaseCrashlytics, "firebaseCrashlytics");
                return new com.quizlet.db.token.c(sharedPreferences2, new com.quizlet.db.token.b(sharedPreferences2), firebaseCrashlytics);
            case 8:
                com.google.firebase.crashlytics.b bVar = (com.google.firebase.crashlytics.b) com.google.firebase.h.c().b(com.google.firebase.crashlytics.b.class);
                if (bVar == null) {
                    throw new NullPointerException("FirebaseCrashlytics component is not present.");
                }
                Intrinsics.checkNotNullExpressionValue(bVar, "getInstance(...)");
                return bVar;
            case 9:
                io.reactivex.rxjava3.core.o networkScheduler = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o databaseScheduler = io.reactivex.rxjava3.schedulers.e.a;
                Intrinsics.checkNotNullExpressionValue(databaseScheduler, "single(...)");
                S6.c(databaseScheduler);
                io.reactivex.rxjava3.core.o computationScheduler = com.quizlet.featuregate.injection.a.k();
                io.reactivex.rxjava3.core.o mainThreadScheduler = com.quizlet.featuregate.injection.a.j();
                DatabaseHelper database = (DatabaseHelper) uVar.v.get();
                Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
                Intrinsics.checkNotNullParameter(databaseScheduler, "databaseScheduler");
                Intrinsics.checkNotNullParameter(computationScheduler, "computationScheduler");
                Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
                Intrinsics.checkNotNullParameter(database, "database");
                return new ExecutionRouter(networkScheduler, databaseScheduler, computationScheduler, mainThreadScheduler, database);
            case 10:
                com.quizlet.shared.usecase.srs.a aVar3 = uVar.b;
                Context context4 = uVar.q();
                com.quizlet.infra.legacysyncengine.net.request.f queryRequestManager = (com.quizlet.infra.legacysyncengine.net.request.f) uVar.P.get();
                com.squareup.otto.c bus = (com.squareup.otto.c) uVar.x.get();
                DatabaseHelper database2 = (DatabaseHelper) uVar.v.get();
                ModelIdentityProvider modelIdentityProvider = (ModelIdentityProvider) uVar.B.get();
                com.quizlet.infra.legacysyncengine.net.listeners.d responseDispatcher = (com.quizlet.infra.legacysyncengine.net.listeners.d) uVar.D.get();
                com.google.android.datatransport.cct.internal.s taskFactory = uVar.s1();
                QueryIdFieldChangeMapper queryIdFieldChangeMapper = (QueryIdFieldChangeMapper) uVar.A.get();
                ExecutionRouter executionRouter2 = (ExecutionRouter) uVar.w.get();
                Intrinsics.checkNotNullParameter(context4, "context");
                Intrinsics.checkNotNullParameter(queryRequestManager, "queryRequestManager");
                Intrinsics.checkNotNullParameter(bus, "bus");
                Intrinsics.checkNotNullParameter(database2, "database");
                Intrinsics.checkNotNullParameter(modelIdentityProvider, "modelIdentityProvider");
                Intrinsics.checkNotNullParameter(responseDispatcher, "responseDispatcher");
                Intrinsics.checkNotNullParameter(taskFactory, "taskFactory");
                Intrinsics.checkNotNullParameter(queryIdFieldChangeMapper, "queryIdFieldChangeMapper");
                Intrinsics.checkNotNullParameter(executionRouter2, "executionRouter");
                try {
                    return new com.quizlet.infra.legacysyncengine.net.c(queryRequestManager, responseDispatcher, taskFactory, queryIdFieldChangeMapper);
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
            case 11:
                com.quizlet.shared.usecase.srs.a aVar4 = uVar.b;
                com.squareup.otto.c bus2 = (com.squareup.otto.c) uVar.x.get();
                QueryIdFieldChangeMapper queryIdFieldChangeMapper2 = (QueryIdFieldChangeMapper) uVar.A.get();
                ExecutionRouter executionRouter3 = (ExecutionRouter) uVar.w.get();
                V requestFactory = uVar.Z0();
                Intrinsics.checkNotNullParameter(bus2, "bus");
                Intrinsics.checkNotNullParameter(queryIdFieldChangeMapper2, "queryIdFieldChangeMapper");
                Intrinsics.checkNotNullParameter(executionRouter3, "executionRouter");
                Intrinsics.checkNotNullParameter(requestFactory, "requestFactory");
                return new com.quizlet.infra.legacysyncengine.net.request.f(queryIdFieldChangeMapper2, requestFactory);
            case 12:
                return new com.squareup.otto.c();
            case 13:
                com.quizlet.shared.usecase.srs.a aVar5 = uVar.b;
                RelationshipGraph relationshipGraph = (RelationshipGraph) uVar.y.get();
                LocalIdMap localIdMap = (LocalIdMap) uVar.z.get();
                Intrinsics.checkNotNullParameter(relationshipGraph, "relationshipGraph");
                Intrinsics.checkNotNullParameter(localIdMap, "localIdMap");
                return new QueryIdFieldChangeMapper(relationshipGraph, localIdMap);
            case 14:
                com.quizlet.shared.usecase.srs.a aVar6 = uVar.b;
                return new RelationshipGraph();
            case 15:
                com.quizlet.shared.usecase.srs.a aVar7 = uVar.b;
                return new LocalIdMap();
            case 16:
                com.quizlet.shared.usecase.srs.a aVar8 = uVar.b;
                DatabaseHelper database3 = (DatabaseHelper) uVar.v.get();
                ExecutionRouter executionRouter4 = (ExecutionRouter) uVar.w.get();
                LocalIdMap localIdMap2 = (LocalIdMap) uVar.z.get();
                RelationshipGraph relationshipGraph2 = (RelationshipGraph) uVar.y.get();
                Intrinsics.checkNotNullParameter(database3, "database");
                Intrinsics.checkNotNullParameter(executionRouter4, "executionRouter");
                Intrinsics.checkNotNullParameter(localIdMap2, "localIdMap");
                Intrinsics.checkNotNullParameter(relationshipGraph2, "relationshipGraph");
                return new ModelIdentityProvider(localIdMap2, relationshipGraph2, database3, executionRouter4);
            case 17:
                return new com.quizlet.infra.legacysyncengine.net.listeners.d((LocalIdMap) uVar.z.get(), (com.quizlet.infra.legacysyncengine.e) uVar.C.get(), (QueryIdFieldChangeMapper) uVar.A.get());
            case 18:
                return new com.quizlet.infra.legacysyncengine.e((RelationshipGraph) uVar.y.get());
            case 19:
                com.quizlet.shared.usecase.folderstudymaterials.c cVar3 = uVar.c;
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                objectMapper.configure(MapperFeature.REQUIRE_SETTERS_FOR_GETTERS, true);
                return objectMapper;
            case 20:
                com.quizlet.shared.usecase.srs.a aVar9 = uVar.b;
                RelationshipGraph graph = (RelationshipGraph) uVar.y.get();
                Intrinsics.checkNotNullParameter(graph, "graph");
                com.quizlet.infra.legacysyncengine.tasks.parse.f fVar2 = new com.quizlet.infra.legacysyncengine.tasks.parse.f();
                fVar2.a = graph;
                return fVar2;
            case 21:
                OkHttpModule okHttpModule = uVar.d;
                SocketFactory socketFactory = SocketFactory.getDefault();
                Intrinsics.checkNotNullExpressionValue(socketFactory, "getDefault(...)");
                TaggedSocketFactory taggedSocketFactory = new TaggedSocketFactory(socketFactory);
                Intrinsics.checkNotNullParameter("9.34.3", "versionName");
                UserAgentInterceptor userAgentInterceptor = new UserAgentInterceptor("9.34.3");
                AcceptLanguageInterceptor acceptLanguageInterceptor = new AcceptLanguageInterceptor();
                UserInfoCache cache = uVar.l0();
                Intrinsics.checkNotNullParameter(cache, "cache");
                String deviceId = cache.getDeviceId().toString();
                Intrinsics.checkNotNullExpressionValue(deviceId, "toString(...)");
                S6.c(deviceId);
                Intrinsics.checkNotNullParameter(deviceId, "deviceId");
                DeviceIdInterceptor deviceIdInterceptor = new DeviceIdInterceptor(deviceId);
                com.quizlet.infra.contracts.session.a appSessionIdProvider = (com.quizlet.infra.contracts.session.a) uVar.G.get();
                okhttp3.s baseUrl = uVar.h();
                Intrinsics.checkNotNullParameter(appSessionIdProvider, "appSessionIdProvider");
                Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
                AppSessionInterceptor appSessionInterceptor = new AppSessionInterceptor(appSessionIdProvider, baseUrl);
                com.quizlet.data.token.a accessTokenProvider = (com.quizlet.data.token.a) uVar.u.get();
                okhttp3.s baseUrl2 = uVar.h();
                Intrinsics.checkNotNullParameter(accessTokenProvider, "accessTokenProvider");
                Intrinsics.checkNotNullParameter(baseUrl2, "baseUrl");
                Intrinsics.checkNotNullParameter("XbSGGchEnA", "clientId");
                return OkHttpModule_ProvideOkHttpClient$api_releaseFactory.a(okHttpModule, taggedSocketFactory, userAgentInterceptor, acceptLanguageInterceptor, deviceIdInterceptor, appSessionInterceptor, new AuthorizationInterceptor(accessTokenProvider, baseUrl2, "XbSGGchEnA"), new ReleaseBuildFlavorInterceptorProvider(), new SecurityChallengeInterceptor((com.quizlet.usecase.b) uVar.H.get(), (com.quizlet.usecase.b) uVar.I.get()), new com.quizlet.humansecurity.b((com.quizlet.humansecurity.c) uVar.K.get(), new PXInterceptor()), (okhttp3.n) uVar.M.get());
            case EventType.WINDOW_STATE /* 22 */:
                ApiModule apiModule = uVar.e;
                AppSessionIdProvider appSessionIdProvider2 = new AppSessionIdProvider();
                appSessionIdProvider2.b = new Date(Long.MIN_VALUE);
                return appSessionIdProvider2;
            case EventType.AUDIO /* 23 */:
                return new com.quizlet.usecase.a(e0.c(Boolean.FALSE));
            case EventType.VIDEO /* 24 */:
                return new com.quizlet.usecase.a(4);
            case EventType.SUBS /* 25 */:
                return new com.quizlet.humansecurity.c(uVar.q(), (com.google.firebase.perf.b) uVar.J.get());
            case EventType.CDN /* 26 */:
                com.google.firebase.perf.logging.a aVar10 = com.google.firebase.perf.b.b;
                com.google.firebase.perf.b bVar2 = (com.google.firebase.perf.b) com.google.firebase.h.c().b(com.google.firebase.perf.b.class);
                Intrinsics.checkNotNullExpressionValue(bVar2, "getInstance(...)");
                S6.c(bVar2);
                return bVar2;
            case 27:
                ApiModule apiModule2 = uVar.e;
                QuizletCookieManager quizletCookieManager = new QuizletCookieManager(new com.quizlet.security.qltj.core.c(new J((InterfaceC1076h) uVar.L.get()), uVar.V()));
                Intrinsics.checkNotNullParameter(quizletCookieManager, "quizletCookieManager");
                return new okhttp3.v(quizletCookieManager);
            case 28:
                Context context5 = uVar.q();
                Intrinsics.checkNotNullParameter(context5, "context");
                kotlin.reflect.n[] nVarArr2 = K.a;
                Intrinsics.checkNotNullParameter(context5, "<this>");
                return (InterfaceC1076h) K.b.a(context5, K.a[0]);
            case 29:
                okhttp3.s baseUrl3 = uVar.h();
                okhttp3.A okHttpClient = (okhttp3.A) uVar.N.get();
                C5184i callAdapter = new C5184i(1);
                Intrinsics.checkNotNullExpressionValue(callAdapter, "createSynchronous(...)");
                retrofit2.converter.jackson.a jsonConverter = QuizletApiClientHelperFactoryModule_ProvideConverterFactoryFactory.a((ObjectMapper) uVar.E.get());
                Intrinsics.checkNotNullParameter(baseUrl3, "baseUrl");
                Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
                Intrinsics.checkNotNullParameter(callAdapter, "callAdapter");
                Intrinsics.checkNotNullParameter(jsonConverter, "jsonConverter");
                return new QuizletApiClient(baseUrl3, okHttpClient, callAdapter, jsonConverter);
            case 30:
                com.quizlet.shared.usecase.srs.a aVar11 = uVar.b;
                DatabaseHelper database4 = (DatabaseHelper) uVar.v.get();
                RelationshipGraph relationshipGraph3 = (RelationshipGraph) uVar.y.get();
                com.quizlet.infra.legacysyncengine.managers.i uiModelSaveManager = (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get();
                ExecutionRouter executionRouter5 = (ExecutionRouter) uVar.w.get();
                V requestFactory2 = uVar.Z0();
                com.quizlet.db.token.a accessTokenProvider2 = (com.quizlet.db.token.a) uVar.u.get();
                Set postSyncHooks = (Set) uVar.T.get();
                Intrinsics.checkNotNullParameter(database4, "database");
                Intrinsics.checkNotNullParameter(relationshipGraph3, "relationshipGraph");
                Intrinsics.checkNotNullParameter(uiModelSaveManager, "uiModelSaveManager");
                Intrinsics.checkNotNullParameter(executionRouter5, "executionRouter");
                Intrinsics.checkNotNullParameter(requestFactory2, "requestFactory");
                Intrinsics.checkNotNullParameter(accessTokenProvider2, "accessTokenProvider");
                Intrinsics.checkNotNullParameter(postSyncHooks, "postSyncHooks");
                return new com.quizlet.infra.legacysyncengine.net.f(relationshipGraph3, uiModelSaveManager, executionRouter5, requestFactory2, accessTokenProvider2, postSyncHooks);
            case 31:
                com.quizlet.shared.usecase.srs.a aVar12 = uVar.b;
                ExecutionRouter executionRouter6 = (ExecutionRouter) uVar.w.get();
                DatabaseHelper database5 = (DatabaseHelper) uVar.v.get();
                ModelIdentityProvider modelIdentityProvider2 = (ModelIdentityProvider) uVar.B.get();
                ModelKeyFieldChangeMapper modelKeyFieldChangeMapper = (ModelKeyFieldChangeMapper) uVar.R.get();
                com.quizlet.infra.legacysyncengine.net.listeners.d responseDispatcher2 = (com.quizlet.infra.legacysyncengine.net.listeners.d) uVar.D.get();
                Intrinsics.checkNotNullParameter(executionRouter6, "executionRouter");
                Intrinsics.checkNotNullParameter(database5, "database");
                Intrinsics.checkNotNullParameter(modelIdentityProvider2, "modelIdentityProvider");
                Intrinsics.checkNotNullParameter(modelKeyFieldChangeMapper, "modelKeyFieldChangeMapper");
                Intrinsics.checkNotNullParameter(responseDispatcher2, "responseDispatcher");
                return new com.quizlet.infra.legacysyncengine.managers.i(executionRouter6, database5, modelIdentityProvider2, modelKeyFieldChangeMapper, responseDispatcher2);
            case 32:
                com.quizlet.shared.usecase.srs.a aVar13 = uVar.b;
                LocalIdMap localIdMap3 = (LocalIdMap) uVar.z.get();
                RelationshipGraph relationshipGraph4 = (RelationshipGraph) uVar.y.get();
                Intrinsics.checkNotNullParameter(localIdMap3, "localIdMap");
                Intrinsics.checkNotNullParameter(relationshipGraph4, "relationshipGraph");
                return new ModelKeyFieldChangeMapper(localIdMap3, relationshipGraph4);
            case 33:
                com.quizlet.shared.usecase.srs.a aVar14 = uVar.b;
                Context context6 = uVar.q();
                DatabaseHelper database6 = (DatabaseHelper) uVar.v.get();
                ExecutionRouter executionRouter7 = (ExecutionRouter) uVar.w.get();
                Intrinsics.checkNotNullParameter(context6, "context");
                Intrinsics.checkNotNullParameter(database6, "database");
                Intrinsics.checkNotNullParameter(executionRouter7, "executionRouter");
                return new HashSet(kotlin.collections.B.j(new com.quizlet.quizletandroid.data.net.synchooks.a(database6, executionRouter7), new com.quizlet.quizletandroid.data.net.synchooks.a(context6, database6)));
            case 34:
                FirebaseMessaging firebaseMessaging2 = FirebaseMessaging.getInstance();
                Intrinsics.checkNotNullExpressionValue(firebaseMessaging2, "getInstance(...)");
                S6.c(firebaseMessaging2);
                return firebaseMessaging2;
            case 35:
                okhttp3.s baseUrl4 = uVar.h();
                C5184i c5184i = new C5184i(1);
                Intrinsics.checkNotNullExpressionValue(c5184i, "createSynchronous(...)");
                com.quizlet.remote.service.G adapter = new com.quizlet.remote.service.G(c5184i);
                retrofit2.converter.moshi.a converter = com.quizlet.featuregate.injection.a.e();
                okhttp3.A okHttpClient2 = (okhttp3.A) uVar.N.get();
                Intrinsics.checkNotNullParameter(baseUrl4, "baseUrl");
                Intrinsics.checkNotNullParameter(adapter, "rxCallAdapter");
                Intrinsics.checkNotNullParameter(converter, "jsonConverter");
                Intrinsics.checkNotNullParameter(okHttpClient2, "okHttpClient");
                Intrinsics.checkNotNullParameter(okHttpClient2, "okHttpClient");
                Intrinsics.checkNotNullParameter(baseUrl4, "baseUrl");
                Intrinsics.checkNotNullParameter(adapter, "adapter");
                Intrinsics.checkNotNullParameter(converter, "converter");
                com.quizlet.data.repository.explanations.textbook.a aVar15 = new com.quizlet.data.repository.explanations.textbook.a(8);
                aVar15.d(baseUrl4);
                Objects.requireNonNull(okHttpClient2, "client == null");
                aVar15.a = okHttpClient2;
                ((ArrayList) aVar15.d).add(adapter);
                aVar15.b(converter);
                L lE = aVar15.e();
                Intrinsics.checkNotNullExpressionValue(lE, "build(...)");
                return lE;
            case 36:
                Context context7 = uVar.q();
                Intrinsics.checkNotNullParameter(context7, "context");
                Object systemService2 = context7.getSystemService("connectivity");
                Intrinsics.e(systemService2, "null cannot be cast to non-null type android.net.ConnectivityManager");
                ConnectivityManager connectivityManager = (ConnectivityManager) systemService2;
                com.quizlet.remote.connectivity.a callback = new com.quizlet.remote.connectivity.a();
                Intrinsics.checkNotNullParameter(connectivityManager, "connectivityManager");
                Intrinsics.checkNotNullParameter(callback, "callback");
                NetworkRequest networkRequestBuild = new NetworkRequest.Builder().build();
                Intrinsics.checkNotNullExpressionValue(networkRequestBuild, "build(...)");
                return new com.quizlet.remote.connectivity.b(connectivityManager, callback, networkRequestBuild);
            case 37:
                return new com.arcao.slf4j.timber.b();
            case 38:
                return new com.quizlet.quizletandroid.util.f(uVar.q(), new com.quizlet.partskit.widgets.icon.b(uVar.q()));
            case 39:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar16 = uVar.f;
                com.quizlet.quizletandroid.managers.audio.g store = (com.quizlet.quizletandroid.managers.audio.g) uVar.d0.get();
                com.quizlet.quizletandroid.audio.players.h player = (com.quizlet.quizletandroid.audio.players.h) uVar.e0.get();
                Intrinsics.checkNotNullParameter(store, "store");
                Intrinsics.checkNotNullParameter(player, "player");
                return new com.quizlet.quizletandroid.managers.audio.h(store, player);
            case RequestError.NETWORK_FAILURE /* 40 */:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar17 = uVar.f;
                okhttp3.A okHttpClient3 = (okhttp3.A) uVar.N.get();
                com.quizlet.quizletandroid.data.cache.b temporaryCache = (com.quizlet.quizletandroid.data.cache.b) uVar.b0.get();
                com.quizlet.quizletandroid.data.cache.c persistentStorage = (com.quizlet.quizletandroid.data.cache.c) uVar.c0.get();
                io.reactivex.rxjava3.core.o ioScheduler = io.reactivex.rxjava3.schedulers.e.c;
                Intrinsics.checkNotNullExpressionValue(ioScheduler, "io(...)");
                S6.c(ioScheduler);
                Intrinsics.checkNotNullParameter(okHttpClient3, "okHttpClient");
                Intrinsics.checkNotNullParameter(temporaryCache, "temporaryCache");
                Intrinsics.checkNotNullParameter(persistentStorage, "persistentStorage");
                Intrinsics.checkNotNullParameter(ioScheduler, "ioScheduler");
                okhttp3.z zVarB = okHttpClient3.b();
                zVarB.c(30L, TimeUnit.SECONDS);
                return new com.quizlet.quizletandroid.managers.audio.g(new okhttp3.A(zVarB), persistentStorage, temporaryCache, ioScheduler);
            case RequestError.NO_DEV_KEY /* 41 */:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar18 = uVar.f;
                Context context8 = uVar.q();
                Intrinsics.checkNotNullParameter(context8, "context");
                return new com.quizlet.quizletandroid.data.cache.b(com.facebook.appevents.g.e(context8, "audio_temporary_cache"));
            case 42:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar19 = uVar.f;
                Context context9 = uVar.q();
                Intrinsics.checkNotNullParameter(context9, "context");
                File cacheDir = com.facebook.appevents.g.e(context9, "audio_persistent_storage");
                Intrinsics.checkNotNullParameter(cacheDir, "cacheDir");
                return new com.quizlet.quizletandroid.data.cache.c(cacheDir);
            case 43:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar20 = uVar.f;
                return new com.quizlet.quizletandroid.audio.players.h();
            case 44:
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a aVar21 = uVar.g;
                com.quizlet.richtext.rendering.d proseMirrorFormatAdapter = (com.quizlet.richtext.rendering.d) uVar.m0.get();
                com.quizlet.richtext.parser.a proseMirrorDocumentParser = (com.quizlet.richtext.parser.a) uVar.n0.get();
                Intrinsics.checkNotNullParameter(proseMirrorFormatAdapter, "proseMirrorFormatAdapter");
                Intrinsics.checkNotNullParameter(proseMirrorDocumentParser, "proseMirrorDocumentParser");
                return new com.quizlet.richtext.rendering.a(proseMirrorFormatAdapter, proseMirrorDocumentParser);
            case 45:
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a aVar22 = uVar.g;
                com.quizlet.quizletandroid.ui.setcreation.managers.n highlightColorResolver = new com.quizlet.quizletandroid.ui.setcreation.managers.n(uVar.D0());
                Intrinsics.checkNotNullParameter(highlightColorResolver, "highlightColorResolver");
                return new com.quizlet.richtext.rendering.d(highlightColorResolver);
            case 46:
                com.quizlet.quizletandroid.injection.modules.a aVar23 = uVar.h;
                EventLogBuilder builder = (EventLogBuilder) uVar.k0.get();
                Intrinsics.checkNotNullParameter(builder, "builder");
                Intrinsics.checkNotNullParameter("9.34.3", "versionName");
                return new EventLogger(builder, "9.34.3");
            case 47:
                com.quizlet.quizletandroid.injection.modules.a aVar24 = uVar.h;
                Executor executor = (Executor) uVar.g0.get();
                com.squareup.otto.c bus3 = (com.squareup.otto.c) uVar.x.get();
                Context context10 = uVar.q();
                EventFileWriter fileWriter = (EventFileWriter) uVar.h0.get();
                ObjectMapper mapper = (ObjectMapper) uVar.i0.get();
                UserInfoCache userInfoCache2 = uVar.l0();
                com.quizlet.data.connectivity.a networkConnectivityManager = (com.quizlet.data.connectivity.a) uVar.X.get();
                com.quizlet.infra.contracts.session.a appSessionIdProvider3 = (com.quizlet.infra.contracts.session.a) uVar.G.get();
                com.quizlet.quizletandroid.managers.session.a appSessionIdManager = new com.quizlet.quizletandroid.managers.session.a(uVar.q());
                EventLogInterceptorManager eventLogInterceptorManager = (EventLogInterceptorManager) uVar.j0.get();
                Intrinsics.checkNotNullParameter(executor, "executor");
                Intrinsics.checkNotNullParameter(bus3, "bus");
                Intrinsics.checkNotNullParameter(context10, "context");
                Intrinsics.checkNotNullParameter(fileWriter, "fileWriter");
                Intrinsics.checkNotNullParameter(mapper, "mapper");
                Intrinsics.checkNotNullParameter(userInfoCache2, "userInfoCache");
                Intrinsics.checkNotNullParameter(networkConnectivityManager, "networkConnectivityManager");
                Intrinsics.checkNotNullParameter(appSessionIdProvider3, "appSessionIdProvider");
                Intrinsics.checkNotNullParameter("9.34.3", "versionName");
                Intrinsics.checkNotNullParameter(appSessionIdManager, "appSessionIdManager");
                Intrinsics.checkNotNullParameter(eventLogInterceptorManager, "eventLogInterceptorManager");
                return new EventLogBuilder(executor, bus3, context10, fileWriter, mapper.writer(), userInfoCache2, networkConnectivityManager, appSessionIdProvider3, "9.34.3", 2601637, appSessionIdManager, eventLogInterceptorManager);
            case 48:
                com.quizlet.quizletandroid.injection.modules.a aVar25 = uVar.h;
                return new ThreadPoolExecutor(1, 1, 1L, TimeUnit.MINUTES, new LinkedBlockingQueue());
            case 49:
                com.quizlet.quizletandroid.injection.modules.a aVar26 = uVar.h;
                return new EventFileWriter();
            case RequestError.RESPONSE_CODE_FAILURE /* 50 */:
                com.quizlet.quizletandroid.injection.modules.a aVar27 = uVar.h;
                ObjectMapper objectMapper2 = new ObjectMapper();
                objectMapper2.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                return objectMapper2;
            case 51:
                com.quizlet.shared.usecase.studiableMetadata.a aVar28 = uVar.i;
                return new EventLogInterceptorManager(new com.quizlet.flipper.di.a());
            case 52:
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a aVar29 = uVar.g;
                com.squareup.moshi.D d = new com.squareup.moshi.D(new com.google.firebase.crashlytics.internal.metadata.p(1));
                Intrinsics.checkNotNullExpressionValue(d, "build(...)");
                return new com.quizlet.richtext.parser.a(d);
            case 53:
                com.quizlet.shared.usecase.folderstudymaterials.b bVar3 = uVar.j;
                okhttp3.A okhttpClient = (okhttp3.A) uVar.N.get();
                com.quizlet.quizletandroid.data.cache.a persistentStorage2 = (com.quizlet.quizletandroid.data.cache.a) uVar.p0.get();
                com.quizlet.quizletandroid.data.cache.c oldPersistentStorage = (com.quizlet.quizletandroid.data.cache.c) uVar.c0.get();
                Intrinsics.checkNotNullParameter(okhttpClient, "okhttpClient");
                Intrinsics.checkNotNullParameter(persistentStorage2, "persistentStorage");
                Intrinsics.checkNotNullParameter(oldPersistentStorage, "oldPersistentStorage");
                okhttp3.z zVarB2 = okhttpClient.b();
                zVarB2.c(30L, TimeUnit.SECONDS);
                return new com.quizlet.quizletandroid.ui.common.images.loading.offline.c(new okhttp3.A(zVarB2), persistentStorage2, oldPersistentStorage);
            case 54:
                com.quizlet.shared.usecase.folderstudymaterials.b bVar4 = uVar.j;
                Context context11 = uVar.q();
                Intrinsics.checkNotNullParameter(context11, "context");
                File cacheDir2 = com.facebook.appevents.g.e(context11, "image_persistent_storage");
                Intrinsics.checkNotNullParameter(cacheDir2, "cacheDir");
                return new com.quizlet.quizletandroid.data.cache.c(cacheDir2);
            case 55:
                com.quizlet.billing.manager.f billingManager = (com.quizlet.billing.manager.f) uVar.s0.get();
                com.quizlet.billing.manager.sku.a skuResolver = (com.quizlet.billing.manager.sku.a) uVar.t0.get();
                Intrinsics.checkNotNullParameter(skuResolver, "skuResolver");
                com.google.android.material.floatingactionbutton.c skuManager = new com.google.android.material.floatingactionbutton.c(skuResolver);
                com.quizlet.billing.manager.sku.a skuResolver2 = (com.quizlet.billing.manager.sku.a) uVar.t0.get();
                Intrinsics.checkNotNullParameter(billingManager, "billingManager");
                Intrinsics.checkNotNullParameter(skuManager, "skuManager");
                Intrinsics.checkNotNullParameter(skuResolver2, "skuResolver");
                return new com.quizlet.billing.subscriptions.i(billingManager, skuManager, skuResolver2);
            case 56:
                Context appContext = uVar.q();
                Intrinsics.checkNotNullParameter(appContext, "appContext");
                return new com.quizlet.billing.manager.f(new com.quizlet.billing.client.provider.a(appContext), uVar.d0(), uVar.e0(), (com.quizlet.billing.model.a) uVar.r0.get());
            case 57:
                return new com.quizlet.billing.model.a();
            case 58:
                com.lyft.android.scissors.b billingUserManager = uVar.e0();
                Intrinsics.checkNotNullParameter(billingUserManager, "billingUserManager");
                return new com.quizlet.billing.manager.sku.a(billingUserManager);
            case 59:
                return new DTBAdRequest(new DTBAdNetworkInfo(DTBAdNetwork.GOOGLE_AD_MANAGER));
            case 60:
                com.quizlet.baserecyclerview.decoration.a aVar30 = new com.quizlet.baserecyclerview.decoration.a(10);
                com.quizlet.usecase.a aVar31 = (com.quizlet.usecase.a) uVar.o.get();
                dagger.internal.a aVarA = dagger.internal.a.a(uVar.w0);
                dagger.internal.a aVarA2 = dagger.internal.a.a(uVar.x0);
                String RELEASE = Build.VERSION.RELEASE;
                Intrinsics.checkNotNullExpressionValue(RELEASE, "RELEASE");
                S6.c(RELEASE);
                UserInfoCache cache2 = uVar.l0();
                Intrinsics.checkNotNullParameter(cache2, "cache");
                String string = cache2.getDeviceId().toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                S6.c(string);
                return new com.quizlet.growthbook.e(aVar30, aVar31, aVarA, aVarA2, string, uVar.V(), (com.google.firebase.perf.b) uVar.J.get());
            case 61:
                Context context12 = uVar.q();
                Intrinsics.checkNotNullParameter(context12, "context");
                kotlin.reflect.n[] nVarArr3 = com.quizlet.local.datastore.preferences.A.a;
                Intrinsics.checkNotNullParameter(context12, "<this>");
                return new C4589z((InterfaceC1076h) com.quizlet.local.datastore.preferences.A.b.a(context12, com.quizlet.local.datastore.preferences.A.a[0]));
            case 62:
                return new ExperimentEnrollmentLogger((EventLogger) uVar.l0.get());
            case 63:
                com.quizlet.quizletandroid.injection.modules.a aVar32 = uVar.h;
                Context context13 = uVar.q();
                com.squareup.otto.c bus4 = (com.squareup.otto.c) uVar.x.get();
                com.quizlet.data.connectivity.a networkConnectivityManager2 = (com.quizlet.data.connectivity.a) uVar.X.get();
                com.quizlet.quizletandroid.managers.h foregroundMonitor = (com.quizlet.quizletandroid.managers.h) uVar.z0.get();
                EventLogCounter logCounter = (EventLogCounter) uVar.h0.get();
                Intrinsics.checkNotNullParameter(context13, "context");
                Intrinsics.checkNotNullParameter(bus4, "bus");
                Intrinsics.checkNotNullParameter(networkConnectivityManager2, "networkConnectivityManager");
                Intrinsics.checkNotNullParameter(foregroundMonitor, "foregroundMonitor");
                Intrinsics.checkNotNullParameter(logCounter, "logCounter");
                final C c = new C();
                c.g = 60000L;
                c.h = true;
                c.c = new Handler();
                c.d = context13;
                c.e = foregroundMonitor;
                c.f = logCounter;
                bus4.d(new B(c));
                io.reactivex.rxjava3.subjects.j jVar = foregroundMonitor.b;
                jVar.getClass();
                final int i2 = 1;
                C4887f c4887f = new C4887f(jVar, i2);
                io.reactivex.rxjava3.functions.d dVar = new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.A
                    @Override // io.reactivex.rxjava3.functions.d
                    public final void accept(Object obj) {
                        com.quizlet.data.connectivity.b bVar5;
                        switch (i2) {
                            case 0:
                                com.quizlet.data.connectivity.b bVar6 = (com.quizlet.data.connectivity.b) obj;
                                C c2 = c;
                                c2.i = bVar6;
                                int i3 = c2.e.a;
                                if (!(i3 > 0) || !bVar6.a || bVar6.c) {
                                    boolean z = bVar6.c;
                                    boolean z2 = bVar6.a;
                                    if (z && !z2) {
                                        Timer timer = c2.a;
                                        if (timer != null) {
                                            timer.cancel();
                                            c2.a = null;
                                            break;
                                        }
                                    } else if (i3 > 0 && z2) {
                                        c2.c(bVar6, false);
                                        break;
                                    }
                                } else {
                                    c2.b();
                                    c2.c(bVar6, false);
                                    break;
                                }
                                break;
                            case 1:
                                C c3 = c;
                                if (!((Boolean) obj).booleanValue()) {
                                    Timer timer2 = c3.a;
                                    if (timer2 != null) {
                                        timer2.cancel();
                                        c3.a = null;
                                        break;
                                    }
                                } else {
                                    com.quizlet.data.connectivity.b bVar7 = c3.i;
                                    if (bVar7 != null && bVar7.a) {
                                        c3.c(bVar7, false);
                                        break;
                                    }
                                }
                                break;
                            default:
                                C c4 = c;
                                if (!((Boolean) obj).booleanValue() && (bVar5 = c4.i) != null && bVar5.a) {
                                    c4.b();
                                    break;
                                }
                                break;
                        }
                    }
                };
                com.quizlet.billing.subscriptions.c cVar4 = new com.quizlet.billing.subscriptions.c(2);
                io.reactivex.rxjava3.internal.functions.b bVar5 = io.reactivex.rxjava3.internal.functions.d.c;
                c4887f.u(dVar, cVar4, bVar5);
                io.reactivex.rxjava3.subjects.j jVar2 = foregroundMonitor.b;
                TimeUnit timeUnit = TimeUnit.SECONDS;
                io.reactivex.rxjava3.core.o oVar = io.reactivex.rxjava3.schedulers.e.b;
                final int i3 = 2;
                jVar2.h(30L, timeUnit, oVar).u(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.A
                    @Override // io.reactivex.rxjava3.functions.d
                    public final void accept(Object obj) {
                        com.quizlet.data.connectivity.b bVar52;
                        switch (i3) {
                            case 0:
                                com.quizlet.data.connectivity.b bVar6 = (com.quizlet.data.connectivity.b) obj;
                                C c2 = c;
                                c2.i = bVar6;
                                int i32 = c2.e.a;
                                if (!(i32 > 0) || !bVar6.a || bVar6.c) {
                                    boolean z = bVar6.c;
                                    boolean z2 = bVar6.a;
                                    if (z && !z2) {
                                        Timer timer = c2.a;
                                        if (timer != null) {
                                            timer.cancel();
                                            c2.a = null;
                                            break;
                                        }
                                    } else if (i32 > 0 && z2) {
                                        c2.c(bVar6, false);
                                        break;
                                    }
                                } else {
                                    c2.b();
                                    c2.c(bVar6, false);
                                    break;
                                }
                                break;
                            case 1:
                                C c3 = c;
                                if (!((Boolean) obj).booleanValue()) {
                                    Timer timer2 = c3.a;
                                    if (timer2 != null) {
                                        timer2.cancel();
                                        c3.a = null;
                                        break;
                                    }
                                } else {
                                    com.quizlet.data.connectivity.b bVar7 = c3.i;
                                    if (bVar7 != null && bVar7.a) {
                                        c3.c(bVar7, false);
                                        break;
                                    }
                                }
                                break;
                            default:
                                C c4 = c;
                                if (!((Boolean) obj).booleanValue() && (bVar52 = c4.i) != null && bVar52.a) {
                                    c4.b();
                                    break;
                                }
                                break;
                        }
                    }
                }, new com.quizlet.billing.subscriptions.c(2), bVar5);
                final int i4 = 0;
                ((com.quizlet.remote.connectivity.b) networkConnectivityManager2).a.a.w(oVar).u(new io.reactivex.rxjava3.functions.d() { // from class: com.quizlet.quizletandroid.A
                    @Override // io.reactivex.rxjava3.functions.d
                    public final void accept(Object obj) {
                        com.quizlet.data.connectivity.b bVar52;
                        switch (i4) {
                            case 0:
                                com.quizlet.data.connectivity.b bVar6 = (com.quizlet.data.connectivity.b) obj;
                                C c2 = c;
                                c2.i = bVar6;
                                int i32 = c2.e.a;
                                if (!(i32 > 0) || !bVar6.a || bVar6.c) {
                                    boolean z = bVar6.c;
                                    boolean z2 = bVar6.a;
                                    if (z && !z2) {
                                        Timer timer = c2.a;
                                        if (timer != null) {
                                            timer.cancel();
                                            c2.a = null;
                                            break;
                                        }
                                    } else if (i32 > 0 && z2) {
                                        c2.c(bVar6, false);
                                        break;
                                    }
                                } else {
                                    c2.b();
                                    c2.c(bVar6, false);
                                    break;
                                }
                                break;
                            case 1:
                                C c3 = c;
                                if (!((Boolean) obj).booleanValue()) {
                                    Timer timer2 = c3.a;
                                    if (timer2 != null) {
                                        timer2.cancel();
                                        c3.a = null;
                                        break;
                                    }
                                } else {
                                    com.quizlet.data.connectivity.b bVar7 = c3.i;
                                    if (bVar7 != null && bVar7.a) {
                                        c3.c(bVar7, false);
                                        break;
                                    }
                                }
                                break;
                            default:
                                C c4 = c;
                                if (!((Boolean) obj).booleanValue() && (bVar52 = c4.i) != null && bVar52.a) {
                                    c4.b();
                                    break;
                                }
                                break;
                        }
                    }
                }, new com.quizlet.billing.subscriptions.c(2), bVar5);
                return c;
            case 64:
                com.quizlet.shared.usecase.srs.a aVar33 = uVar.b;
                com.quizlet.quizletandroid.managers.h hVar = new com.quizlet.quizletandroid.managers.h();
                hVar.a = 0;
                hVar.b = new io.reactivex.rxjava3.subjects.j();
                return hVar;
            case 65:
                return new C4625h(uVar, 2);
            case 66:
                return new C4625h(uVar, 0);
            case 67:
                return new C4625h(uVar, 1);
            case 68:
                return new C4625h(uVar, 3);
            case 69:
                return new C4625h(uVar, 4);
            case 70:
                return new C4625h(uVar, 5);
            case 71:
                return new com.quizlet.quizletandroid.util.n(uVar.q(), (com.quizlet.quizletandroid.managers.audio.g) uVar.d0.get(), (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) uVar.q0.get(), (DbSizeHelper) uVar.v.get(), (EventLogger) uVar.l0.get(), com.quizlet.featuregate.injection.a.l());
            case 72:
                return new p(this, 0);
            case 73:
                com.quizlet.quizletandroid.injection.modules.a aVar34 = uVar.h;
                IQuizletApiClient apiClient = (IQuizletApiClient) uVar.O.get();
                Executor executor2 = (Executor) uVar.g0.get();
                ObjectMapper loggingMapper = (ObjectMapper) uVar.i0.get();
                Intrinsics.checkNotNullParameter(loggingMapper, "loggingMapper");
                ObjectReader loggingReader = loggingMapper.readerFor(HashMapEventLog.class);
                Intrinsics.checkNotNullExpressionValue(loggingReader, "readerFor(...)");
                S6.c(loggingReader);
                ObjectReader apiReader = uVar.e();
                ObjectWriter apiWriter = uVar.f();
                Context context14 = uVar.q();
                EventFileWriter fileWriter2 = (EventFileWriter) uVar.h0.get();
                io.reactivex.rxjava3.core.o networkScheduler2 = com.quizlet.featuregate.injection.a.l();
                C uploadSuccessListener = (C) uVar.A0.get();
                IHttpErrorManager.HttpErrorManager httpErrorManager = IHttpErrorManager.HttpErrorManager.a;
                Intrinsics.checkNotNullParameter(apiClient, "apiClient");
                Intrinsics.checkNotNullParameter(executor2, "executor");
                Intrinsics.checkNotNullParameter(loggingReader, "loggingReader");
                Intrinsics.checkNotNullParameter(apiReader, "apiReader");
                Intrinsics.checkNotNullParameter(apiWriter, "apiWriter");
                Intrinsics.checkNotNullParameter(context14, "context");
                Intrinsics.checkNotNullParameter(fileWriter2, "fileWriter");
                Intrinsics.checkNotNullParameter(networkScheduler2, "networkScheduler");
                Intrinsics.checkNotNullParameter(uploadSuccessListener, "uploadSuccessListener");
                Intrinsics.checkNotNullParameter(httpErrorManager, "httpErrorManager");
                return new EventLogUploader(apiClient, executor2, loggingReader, apiReader, apiWriter, context14.getFilesDir(), fileWriter2, networkScheduler2, uploadSuccessListener, httpErrorManager);
            case 74:
                return new p(this, 1);
            case 75:
                Context context15 = uVar.q();
                Intrinsics.checkNotNullParameter(context15, "context");
                kotlin.reflect.n[] nVarArr4 = com.quizlet.local.datastore.models.metering.k.a;
                Intrinsics.checkNotNullParameter(context15, "<this>");
                return (InterfaceC1076h) com.quizlet.local.datastore.models.metering.k.b.a(context15, com.quizlet.local.datastore.models.metering.k.a[0]);
            case 76:
                return new p(this, 2);
            case AndroidTcfDataLoader.COMSCORE_VENDOR_INDEX /* 77 */:
                return new p(this, 3);
            case 78:
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                com.quizlet.local.cache.caches.c cVar5 = new com.quizlet.local.cache.caches.c();
                cVar5.a = new com.quizlet.local.cache.e(86400L);
                cVar5.b = com.quizlet.time.b.a();
                return cVar5;
            case 79:
                return new com.quizlet.braze.f(uVar.q());
            case 80:
                OTSdkParams.SdkParamsBuilder otBannerHeightRatio = OTSdkParams.SdkParamsBuilder.newInstance().setOtBannerHeightRatio(OTBannerHeightRatio.TWO_THIRD);
                OTUXParams oTUXParamsBuild = OTUXParams.OTUXParamsBuilder.newInstance().setUXParams(new JSONObject("\n{\n  \"UIConfig\": {\n    \"globalTheme\": {\n      \"shouldShowlinkUnderline\": true,\n      \"linkColor\": \"\"\n    },\n    \"pageHeader\": {\n      \"fontName\": \"\",\n      \"fontSize\": \"\",\n      \"fontTextStyle\": 1,\n      \"textColor\": \"\"\n    },\n    \"bannerTheme\": {\n      \"backgroundColor\": \"\",\n      \"summary\": {\n        \"title\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": 16,\n          \"fontTextStyle\": 1,\n          \"textAlignment\": 5,\n          \"textColor\": \"\"\n        },\n        \"description\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": 14,\n          \"fontTextStyle\": 1,\n          \"textAlignment\": 5,\n          \"textColor\": \"\"\n        }\n      },\n      \"buttons\": {\n        \"closeButtonColor\": \"\",\n        \"closeButton\": {\n          \"backgroundColor\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"acceptAll\": {\n          \"backgroundColor\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"rejectAll\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"showPreferences\": {\n          \"backgroundColor\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        }\n      },\n      \"links\": {\n        \"policyLink\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"vendorList\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textAlignment\": 4,\n          \"textColor\": \"\"\n        }\n      }\n    },\n    \"preferenceCenterTheme\": {\n      \"backgroundColor\": \"\",\n      \"lineBreakColor\": \"\",\n      \"toggleThumbColorOn\": \"\",\n      \"toggleThumbColorOff\": \"\",\n      \"toggleTrackColor\": \"\",\n      \"showLogoOnPC\": true,\n      \"summary\": {\n        \"title\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"description\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textAlignment\": 5,\n          \"textColor\": \"\"\n        }\n      },\n      \"purposesTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"purposesAlwaysActiveStatus\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"buttons\": {\n        \"closeButtonColor\": \"\",\n        \"closeButton\": {\n          \"backgroundColor\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"backButtonColor\": \"\",\n        \"acceptAll\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"rejectAll\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"confirmMyChoice\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        }\n      },\n      \"links\": {\n        \"policyLink\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"vendorList\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        }\n      }\n    },\n    \"purposeDetailsTheme\": {\n      \"backgroundColor\": \"\",\n      \"lineBreakColor\": \"\",\n      \"toggleThumbColorOn\": \"\",\n      \"toggleThumbColorOff\": \"\",\n      \"toggleTrackColor\": \"\",\n      \"backButtonColor\": \"\",\n      \"groupSummary\": {\n        \"title\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"description\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"textAlignment\": 5\n        }\n      },\n      \"consentTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"legitInterestTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"purposesAlwaysActiveStatus\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"links\": {\n        \"sdkList\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"vendorList\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"fullLegalText\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        }\n      }\n    },\n    \"vendorListTheme\": {\n      \"backgroundColor\": \"\",\n      \"lineBreakColor\": \"\",\n      \"toggleThumbColorOn\": \"\",\n      \"toggleThumbColorOff\": \"\",\n      \"toggleTrackColor\": \"\",\n      \"filterOnColor\": \"\",\n      \"filterOffColor\": \"\",\n      \"filterSelectionColor\": \"\",\n      \"searchBar\": {\n        \"textColor\": \"\",\n        \"placeholderTextColor\": \"\",\n        \"backgroundColor\": \"\",\n        \"iconColor\": \"\",\n        \"borderColor\": \"\",\n        \"clearButtonColor\": \"\",\n        \"borderWidth\": \"\",\n        \"borderRadius\": \"\"\n      },\n      \"filterNavText\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"title\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"allowAllToggleText\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"filterItemTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"buttons\": {\n        \"backButtonColor\": \"\",\n        \"confirmMyChoices\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        },\n        \"applyFilter\": {\n          \"backgroundColor\": \"\",\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\",\n          \"borderColor\": \"\",\n          \"borderWidth\": \"\",\n          \"borderRadius\": \"\"\n        }\n      }\n    },\n    \"vendorDetailsTheme\": {\n      \"backgroundColor\": \"\",\n      \"toggleThumbColorOn\": \"\",\n      \"toggleThumbColorOff\": \"\",\n      \"toggleTrackColor\": \"\",\n      \"backButtonColor\": \"\",\n      \"title\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"detailsSummary\": {\n        \"title\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"description\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        }\n      },\n      \"consentTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"legitInterestTitle\": {\n        \"typeFaceKey\": \"\",\n        \"fontName\": \"\",\n        \"fontSize\": \"\",\n        \"fontTextStyle\": 1,\n        \"textColor\": \"\"\n      },\n      \"links\": {\n        \"privacyNotice\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        }\n      }\n    },\n    \"sdkListTheme\": {\n      \"backgroundColor\": \"\",\n      \"lineBreakColor\": \"\",\n      \"filterOnColor\": \"\",\n      \"filterOffColor\": \"\",\n      \"searchBar\": {\n        \"textColor\": \"\",\n        \"placeholderTextColor\": \"\",\n        \"backgroundColor\": \"\",\n        \"iconColor\": \"\",\n        \"borderColor\": \"\",\n        \"clearButtonColor\": \"\",\n        \"borderWidth\": \"\",\n        \"borderRadius\": \"\"\n      },\n      \"summary\": {\n        \"title\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"description\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        }\n      },\n      \"filterList\": {\n        \"selectionColor\": \"\",\n        \"navItem\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"sdkItem\": {\n          \"typeFaceKey\": \"\",\n          \"fontName\": \"\",\n          \"fontSize\": \"\",\n          \"fontTextStyle\": 1,\n          \"textColor\": \"\"\n        },\n        \"buttons\": {\n          \"backButtonColor\": \"\",\n          \"applyFilter\": {\n            \"backgroundColor\": \"\",\n            \"typeFaceKey\": \"\",\n            \"fontName\": \"\",\n            \"fontSize\": \"\",\n            \"fontTextStyle\": 1,\n            \"textColor\": \"\",\n            \"borderColor\": \"\",\n            \"borderWidth\": \"\",\n            \"borderRadius\": \"\"\n          }\n        }\n      }\n    }\n  }\n}\n")).build();
                Intrinsics.checkNotNullExpressionValue(oTUXParamsBuild, "build(...)");
                OTSdkParams oTSdkParamsBuild = otBannerHeightRatio.setOTUXParams(oTUXParamsBuild).build();
                Intrinsics.checkNotNullExpressionValue(oTSdkParamsBuild, "build(...)");
                S6.c(oTSdkParamsBuild);
                return new com.quizlet.features.consent.onetrust.d(oTSdkParamsBuild, dagger.internal.a.a(uVar.Q0));
            case 81:
                Context context16 = uVar.q();
                Intrinsics.checkNotNullParameter(context16, "context");
                return new OTPublishersHeadlessSDK(context16);
            case 82:
                dagger.internal.a onLowMemoryHandler = dagger.internal.a.a(uVar.S0);
                Intrinsics.checkNotNullParameter(onLowMemoryHandler, "onLowMemoryHandler");
                return new com.quizlet.quizletandroid.util.h(onLowMemoryHandler);
            case 83:
                com.quizlet.shared.usecase.session.c cVar6 = (com.quizlet.shared.usecase.session.c) com.quizlet.shared.usecase.di.f.f.getValue();
                S6.c(cVar6);
                return cVar6;
            case 84:
                Context context17 = uVar.q();
                Intrinsics.checkNotNullParameter(context17, "context");
                FirebaseAnalytics firebaseAnalytics = FirebaseAnalytics.getInstance(context17);
                Intrinsics.checkNotNullExpressionValue(firebaseAnalytics, "getInstance(...)");
                S6.c(firebaseAnalytics);
                return firebaseAnalytics;
            case 85:
                return new com.quizlet.usecase.a(e0.b(1, 1, null, 4));
            case 86:
                return new com.quizlet.quizletandroid.interactor.t((com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), new retrofit2.adapter.rxjava3.d(28), (com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), (com.quizlet.braze.e) uVar.X0.get(), com.quizlet.featuregate.injection.a.d());
            case 87:
                return new com.quizlet.braze.e((Braze) uVar.W0.get(), (com.quizlet.braze.a) uVar.P0.get());
            case 88:
                Context context18 = uVar.q();
                Intrinsics.checkNotNullParameter(context18, "context");
                Braze companion = Braze.Companion.getInstance(context18);
                S6.c(companion);
                return companion;
            case 89:
                com.squareup.otto.c bus5 = (com.squareup.otto.c) uVar.x.get();
                IQuizletApiClient apiClient2 = (IQuizletApiClient) uVar.O.get();
                io.reactivex.rxjava3.core.o networkScheduler3 = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o mainThreadScheduler2 = com.quizlet.featuregate.injection.a.j();
                Intrinsics.checkNotNullParameter(bus5, "bus");
                Intrinsics.checkNotNullParameter(apiClient2, "apiClient");
                Intrinsics.checkNotNullParameter(networkScheduler3, "networkScheduler");
                Intrinsics.checkNotNullParameter(mainThreadScheduler2, "mainThreadScheduler");
                return new com.quizlet.quizletandroid.managers.g(bus5, apiClient2, networkScheduler3, mainThreadScheduler2);
            case SubsamplingScaleImageView.ORIENTATION_90 /* 90 */:
                okhttp3.s baseUrl5 = uVar.h();
                retrofit2.converter.moshi.a converter2 = com.quizlet.featuregate.injection.a.e();
                okhttp3.A okHttpClient4 = (okhttp3.A) uVar.N.get();
                Intrinsics.checkNotNullParameter(baseUrl5, "baseUrl");
                Intrinsics.checkNotNullParameter(converter2, "jsonConverter");
                Intrinsics.checkNotNullParameter(okHttpClient4, "okHttpClient");
                Intrinsics.checkNotNullParameter(okHttpClient4, "okHttpClient");
                Intrinsics.checkNotNullParameter(baseUrl5, "baseUrl");
                Intrinsics.checkNotNullParameter(converter2, "converter");
                com.quizlet.data.repository.explanations.textbook.a aVar35 = new com.quizlet.data.repository.explanations.textbook.a(8);
                aVar35.d(baseUrl5);
                Objects.requireNonNull(okHttpClient4, "client == null");
                aVar35.a = okHttpClient4;
                aVar35.b(converter2);
                L lE2 = aVar35.e();
                Intrinsics.checkNotNullExpressionValue(lE2, "build(...)");
                return lE2;
            case 91:
                Context context19 = uVar.a.a;
                S6.c(context19);
                return new com.quizlet.security.challenge.core.i(context19, uVar.Q(), (com.quizlet.usecase.a) uVar.H.get(), (com.quizlet.usecase.a) uVar.I.get(), new com.quizlet.features.emailconfirmation.logging.a((EventLogger) uVar.l0.get(), 4), (com.quizlet.usecase.a) uVar.o.get());
            case 92:
                return new io.reactivex.rxjava3.disposables.a();
            case 93:
                return new com.quizlet.quizletandroid.ui.joincontenttofolder.k(new com.quizlet.data.repository.searchexplanations.c(uVar.H(), u.v()), uVar.U(), new com.quizlet.data.repository.widget.b(uVar.H(), u.v()), new androidx.work.impl.model.e(uVar.n(), u.v()), new androidx.work.impl.model.l(uVar.n(), u.v()), uVar.l0(), uVar.l(), (com.quizlet.offline.managers.b) uVar.d1.get());
            case 94:
                com.quizlet.shared.usecase.folderstudymaterials.d dVar2 = uVar.k;
                EventLogger eventLogger = (EventLogger) uVar.l0.get();
                com.quizlet.data.connectivity.a networkConnectivityManager3 = (com.quizlet.data.connectivity.a) uVar.X.get();
                io.reactivex.rxjava3.core.o mainScheduler = com.quizlet.featuregate.injection.a.j();
                androidx.work.impl.model.c userProperties = uVar.m0();
                com.quizlet.quizletandroid.managers.audio.g audioResources = (com.quizlet.quizletandroid.managers.audio.g) uVar.d0.get();
                com.quizlet.quizletandroid.ui.common.images.loading.offline.c imageResources = (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) uVar.q0.get();
                QueryIdFieldChangeMapper mQueryIdFieldChangeMapper = (QueryIdFieldChangeMapper) uVar.A.get();
                com.google.android.datatransport.cct.internal.s mTaskFactory = uVar.s1();
                V mRequestFactory = uVar.Z0();
                com.quizlet.infra.legacysyncengine.net.listeners.d mRespDispatcher = (com.quizlet.infra.legacysyncengine.net.listeners.d) uVar.D.get();
                io.reactivex.rxjava3.core.o networkScheduler4 = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o computationScheduler2 = com.quizlet.featuregate.injection.a.k();
                io.reactivex.rxjava3.core.o ioScheduler2 = io.reactivex.rxjava3.schedulers.e.c;
                Intrinsics.checkNotNullExpressionValue(ioScheduler2, "io(...)");
                S6.c(ioScheduler2);
                Intrinsics.checkNotNullParameter(audioResources, "audioResourceStore");
                Intrinsics.checkNotNullParameter(imageResources, "imageResourceStore");
                Intrinsics.checkNotNullParameter(mQueryIdFieldChangeMapper, "queryIdFieldChangeMapper");
                Intrinsics.checkNotNullParameter(mTaskFactory, "taskFactory");
                Intrinsics.checkNotNullParameter(mRequestFactory, "requestFactory");
                Intrinsics.checkNotNullParameter(mRespDispatcher, "respDispatcher");
                Intrinsics.checkNotNullParameter(networkScheduler4, "networkScheduler");
                Intrinsics.checkNotNullParameter(computationScheduler2, "computationScheduler");
                Intrinsics.checkNotNullParameter(ioScheduler2, "ioScheduler");
                Intrinsics.checkNotNullParameter(audioResources, "audioResources");
                Intrinsics.checkNotNullParameter(imageResources, "imageResources");
                Intrinsics.checkNotNullParameter(mQueryIdFieldChangeMapper, "mQueryIdFieldChangeMapper");
                Intrinsics.checkNotNullParameter(mTaskFactory, "mTaskFactory");
                Intrinsics.checkNotNullParameter(mRequestFactory, "mRequestFactory");
                Intrinsics.checkNotNullParameter(mRespDispatcher, "mRespDispatcher");
                Intrinsics.checkNotNullParameter(networkScheduler4, "networkScheduler");
                Intrinsics.checkNotNullParameter(computationScheduler2, "computationScheduler");
                Intrinsics.checkNotNullParameter(ioScheduler2, "ioScheduler");
                com.google.android.datatransport.cct.internal.s setModelManager = new com.google.android.datatransport.cct.internal.s();
                setModelManager.b = audioResources;
                setModelManager.c = imageResources;
                setModelManager.d = mQueryIdFieldChangeMapper;
                setModelManager.e = mTaskFactory;
                setModelManager.f = mRequestFactory;
                setModelManager.g = mRespDispatcher;
                setModelManager.a = networkScheduler4;
                setModelManager.h = computationScheduler2;
                setModelManager.i = ioScheduler2;
                io.reactivex.rxjava3.core.o logicScheduler = com.quizlet.featuregate.injection.a.k();
                com.quizlet.infra.legacysyncengine.managers.i saveManager = (com.quizlet.infra.legacysyncengine.managers.i) uVar.S.get();
                Intrinsics.checkNotNullParameter(saveManager, "saveManager");
                com.quizlet.local.ormlite.models.term.b offlineEntityPersistenceManager = new com.quizlet.local.ormlite.models.term.b(saveManager);
                com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
                Intrinsics.checkNotNullParameter(networkConnectivityManager3, "networkConnectivityManager");
                Intrinsics.checkNotNullParameter(mainScheduler, "mainScheduler");
                Intrinsics.checkNotNullParameter(userProperties, "userProperties");
                Intrinsics.checkNotNullParameter(setModelManager, "setModelManager");
                Intrinsics.checkNotNullParameter(logicScheduler, "logicScheduler");
                Intrinsics.checkNotNullParameter(offlineEntityPersistenceManager, "offlineEntityPersistenceManager");
                Intrinsics.checkNotNullParameter(loader, "loader");
                return new com.quizlet.offline.managers.i(eventLogger, networkConnectivityManager3, mainScheduler, userProperties, logicScheduler, setModelManager, offlineEntityPersistenceManager, loader);
            case 95:
                com.quizlet.shared.usecase.srs.a aVar36 = uVar.b;
                UserInfoCache userInfoCache3 = uVar.l0();
                ObjectWriter objectWriter = uVar.f();
                com.quizlet.infra.legacysyncengine.managers.h serverModelSaveManager = (com.quizlet.infra.legacysyncengine.managers.h) uVar.f1.get();
                androidx.work.impl.model.n permissions = uVar.e1();
                IQuizletApiClient apiClient3 = (IQuizletApiClient) uVar.O.get();
                io.reactivex.rxjava3.core.o networkScheduler5 = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o mainScheduler2 = com.quizlet.featuregate.injection.a.j();
                Intrinsics.checkNotNullParameter(userInfoCache3, "userInfoCache");
                Intrinsics.checkNotNullParameter(objectWriter, "objectWriter");
                Intrinsics.checkNotNullParameter(serverModelSaveManager, "serverModelSaveManager");
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                Intrinsics.checkNotNullParameter(apiClient3, "apiClient");
                Intrinsics.checkNotNullParameter(networkScheduler5, "networkScheduler");
                Intrinsics.checkNotNullParameter(mainScheduler2, "mainScheduler");
                return new com.quizlet.features.setpage.utils.setpermissions.f(userInfoCache3, objectWriter, serverModelSaveManager, permissions, apiClient3, networkScheduler5, mainScheduler2);
            case 96:
                com.quizlet.shared.usecase.srs.a aVar37 = uVar.b;
                ExecutionRouter executionRouter8 = (ExecutionRouter) uVar.w.get();
                DatabaseHelper database7 = (DatabaseHelper) uVar.v.get();
                ModelIdentityProvider modelIdentityProvider3 = (ModelIdentityProvider) uVar.B.get();
                com.quizlet.infra.legacysyncengine.net.listeners.d responseDispatcher3 = (com.quizlet.infra.legacysyncengine.net.listeners.d) uVar.D.get();
                Intrinsics.checkNotNullParameter(executionRouter8, "executionRouter");
                Intrinsics.checkNotNullParameter(database7, "database");
                Intrinsics.checkNotNullParameter(modelIdentityProvider3, "modelIdentityProvider");
                Intrinsics.checkNotNullParameter(responseDispatcher3, "responseDispatcher");
                return new com.quizlet.infra.legacysyncengine.managers.h(executionRouter8, database7, modelIdentityProvider3, responseDispatcher3);
            case 97:
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                return new com.quizlet.local.cache.g(60L);
            case 98:
                Context contextQ = uVar.q();
                com.squareup.otto.c cVar7 = (com.squareup.otto.c) uVar.x.get();
                com.quizlet.quizletandroid.managers.g gVar = (com.quizlet.quizletandroid.managers.g) uVar.Z0.get();
                com.quizlet.quizletandroid.managers.c cVar8 = new com.quizlet.quizletandroid.managers.c();
                cVar8.c = false;
                cVar8.d = false;
                cVar8.b = contextQ;
                cVar8.a = gVar;
                cVar7.d(new com.quizlet.quizletandroid.managers.b(cVar8));
                return cVar8;
            case 99:
                return new com.quizlet.quizletandroid.ui.base.b();
            default:
                throw new AssertionError(i);
        }
    }

    @Override // javax.inject.a
    public final Object get() {
        int i = 3;
        int i2 = 25;
        int i3 = 2;
        int i4 = 29;
        int i5 = 1;
        int i6 = 0;
        int i7 = this.b;
        int i8 = i7 / 100;
        if (i8 == 0) {
            return a();
        }
        if (i8 != 1) {
            throw new AssertionError(i7);
        }
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        u uVar = this.a;
        switch (i7) {
            case 100:
                return new com.quizlet.quizletandroid.ui.base.bus.a((com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get(), uVar.u0());
            case 101:
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                com.quizlet.local.cache.caches.a aVar = new com.quizlet.local.cache.caches.a();
                aVar.a = new com.quizlet.local.cache.e(180L);
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                aVar.b = new com.quizlet.local.cache.e(180L);
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                aVar.c = new com.quizlet.local.cache.e(180L);
                Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
                aVar.d = new com.quizlet.local.cache.e(180L);
                return aVar;
            case 102:
                Context context = uVar.q();
                Intrinsics.checkNotNullParameter(context, "context");
                String str = LoginNavActivity.i;
                Intent intentA = com.google.android.gms.internal.mlkit_vision_document_scanner.B.a(context);
                intentA.addFlags(268468224);
                return intentA;
            case 103:
                Context context2 = uVar.q();
                Intrinsics.checkNotNullParameter(context2, "context");
                kotlin.reflect.n[] nVarArr = Q.a;
                Intrinsics.checkNotNullParameter(context2, "<this>");
                return (InterfaceC1076h) Q.b.a(context2, Q.a[0]);
            case 104:
                com.quizlet.local.cache.caches.b bVar = com.quizlet.local.cache.caches.b.c;
                S6.c(bVar);
                return bVar;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_CONSENT_EXPIRED /* 105 */:
                Context context3 = uVar.q();
                Intrinsics.checkNotNullParameter(context3, "context");
                kotlin.reflect.n[] nVarArr2 = O.a;
                Intrinsics.checkNotNullParameter(context3, "<this>");
                return (InterfaceC1076h) O.b.a(context3, O.a[0]);
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SERVICE_SPECIFIC_OFF /* 106 */:
                Context context4 = uVar.q();
                Intrinsics.checkNotNullParameter(context4, "context");
                kotlin.reflect.n[] nVarArr3 = D0.a;
                Intrinsics.checkNotNullParameter(context4, "<this>");
                return (InterfaceC1076h) D0.b.a(context4, D0.a[0]);
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED /* 107 */:
                Context context5 = uVar.a.a;
                S6.c(context5);
                Intrinsics.checkNotNullParameter(context5, "context");
                return androidx.datastore.preferences.core.e.e(new com.airbnb.lottie.network.c(new com.quizlet.features.universaluploadflow.flashcards.d(20)), new androidx.navigation.compose.w(context5, 6), 6);
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_BACKWARD_COMPATIBILITY /* 108 */:
                CookieManager cookieManager = CookieManager.getInstance();
                Intrinsics.checkNotNullExpressionValue(cookieManager, "getInstance(...)");
                S6.c(cookieManager);
                return cookieManager;
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION /* 109 */:
                Context context6 = uVar.q();
                Intrinsics.checkNotNullParameter(context6, "context");
                String str2 = SearchActivity.q;
                return N5.d(context6, null);
            case OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SHOW_BANNER_CALLED /* 110 */:
                return new com.quizlet.usecase.a(5);
            case 111:
                return new com.quizlet.ads.g();
            case ContentType.LONG_FORM_ON_DEMAND /* 112 */:
                return new com.quizlet.features.flashcards.autoplay.o();
            case ContentType.LIVE /* 113 */:
                return new com.quizlet.quizletandroid.util.a((com.quizlet.infra.legacysyncengine.net.f) uVar.U.get(), (com.quizlet.quizletandroid.util.e) uVar.x1.get(), (EventLogger) uVar.l0.get(), uVar.l(), new com.quizlet.quizletandroid.util.d());
            case 114:
                com.quizlet.shared.usecase.srs.a aVar2 = uVar.b;
                com.quizlet.infra.legacysyncengine.net.c loader = (com.quizlet.infra.legacysyncengine.net.c) uVar.Q.get();
                com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                Intrinsics.checkNotNullParameter(loader, "loader");
                Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
                return new com.quizlet.quizletandroid.util.e(loader, loggedInUserManager);
            case 115:
                com.quizlet.ads.b bVarO0 = uVar.o0();
                com.google.mlkit.vision.documentscanner.internal.c cVar = new com.google.mlkit.vision.documentscanner.internal.c(uVar.v0);
                com.google.android.material.shape.e eVar = new com.google.android.material.shape.e(i4);
                C4641h c4641h = new C4641h(5);
                C4641h c4641h2 = new C4641h(i3);
                Context context7 = uVar.a.a;
                S6.c(context7);
                com.quizlet.quizletandroid.ui.common.ads.I i9 = new com.quizlet.quizletandroid.ui.common.ads.I(eVar, c4641h, c4641h2, new com.quizlet.data.repository.searchexplanations.c(context7, new C4636c(new C4641h(i))));
                com.quizlet.data.repository.course.membership.c cVar2 = new com.quizlet.data.repository.course.membership.c(new com.quizlet.shared.usecase.studiableMetadata.a(i2), uVar.m0(), (com.quizlet.data.connectivity.a) uVar.X.get());
                kotlinx.coroutines.scheduling.e eVar2 = kotlinx.coroutines.O.a;
                kotlinx.coroutines.android.d dVar = kotlinx.coroutines.internal.m.a;
                S6.c(dVar);
                return new com.quizlet.quizletandroid.ui.common.ads.E(bVarO0, cVar, i9, cVar2, dVar, com.quizlet.featuregate.injection.a.d());
            case 116:
                com.quizlet.ads.b bVarO02 = uVar.o0();
                AdManagerAdRequest.Builder adManagerAdRequest = new AdManagerAdRequest.Builder();
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a bannerAdUnitCreator = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a(i6);
                com.quizlet.data.interactor.course.a adManagerAdViewCreator = new com.quizlet.data.interactor.course.a(new com.quizlet.quizletandroid.ui.common.ads.prebid.n());
                Intrinsics.checkNotNullParameter(adManagerAdRequest, "adManagerAdRequest");
                Intrinsics.checkNotNullParameter(bannerAdUnitCreator, "bannerAdUnitCreator");
                Intrinsics.checkNotNullParameter(adManagerAdViewCreator, "adManagerAdViewCreator");
                com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar3 = new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(new com.quizlet.quizletandroid.ui.common.ads.prebid.g(adManagerAdViewCreator, bannerAdUnitCreator, adManagerAdRequest));
                com.quizlet.data.repository.course.membership.c cVar4 = new com.quizlet.data.repository.course.membership.c(new com.quizlet.shared.usecase.studiableMetadata.a(i2), uVar.m0(), (com.quizlet.data.connectivity.a) uVar.X.get());
                kotlinx.coroutines.scheduling.e eVar3 = kotlinx.coroutines.O.a;
                kotlinx.coroutines.android.d dVar2 = kotlinx.coroutines.internal.m.a;
                S6.c(dVar2);
                AbstractC5040y abstractC5040yD = com.quizlet.featuregate.injection.a.d();
                Context context8 = uVar.a.a;
                S6.c(context8);
                return new com.quizlet.quizletandroid.ui.common.ads.prebid.m(bVarO02, cVar3, cVar4, dVar2, abstractC5040yD, new com.quizlet.data.repository.searchexplanations.c(context8, new C4636c(new C4641h(i))));
            case 117:
                return new com.quizlet.quizletandroid.util.g();
            case 118:
                Context context9 = uVar.q();
                Intrinsics.checkNotNullParameter(context9, "context");
                kotlin.reflect.n[] nVarArr4 = AbstractC4569e.a;
                Intrinsics.checkNotNullParameter(context9, "<this>");
                return (InterfaceC1076h) AbstractC4569e.b.a(context9, AbstractC4569e.a[0]);
            case 119:
                return new com.quizlet.features.infra.basestudy.manager.d(new StudyFunnelEventLogger((EventLogger) uVar.l0.get()));
            case 120:
                IQuizletApiClient apiClient = (IQuizletApiClient) uVar.O.get();
                io.reactivex.rxjava3.core.o networkScheduler = com.quizlet.featuregate.injection.a.l();
                io.reactivex.rxjava3.core.o mainThreadScheduler = com.quizlet.featuregate.injection.a.j();
                com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager2 = (com.quizlet.infra.legacysyncengine.managers.d) uVar.Z.get();
                Intrinsics.checkNotNullParameter(apiClient, "apiClient");
                Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
                Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
                Intrinsics.checkNotNullParameter(loggedInUserManager2, "loggedInUserManager");
                return new com.quizlet.quizletandroid.ui.setcreation.managers.v(apiClient, networkScheduler, mainThreadScheduler, loggedInUserManager2.e.getPersonId());
            case ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND /* 121 */:
                com.quizlet.shared.usecase.srs.a aVar3 = uVar.b;
                com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a aVar4 = new com.quizlet.quizletandroid.ui.setcreation.managers.interfaces.a();
                aVar4.a = true;
                return aVar4;
            case ContentType.USER_GENERATED_LONG_FORM_ON_DEMAND /* 122 */:
                return new SearchEventLogger.Impl((EventLogger) uVar.l0.get());
            case ContentType.USER_GENERATED_LIVE /* 123 */:
                Context context10 = uVar.q();
                Intrinsics.checkNotNullParameter(context10, "context");
                String str3 = LoginNavActivity.i;
                Intent intentB = AbstractC4178x.b(context10, "context", context10, LoginNavActivity.class);
                intentB.putExtra("navigationRoute", "login");
                return intentB;
            case 124:
                return new com.quizlet.humansecurity.d((com.quizlet.humansecurity.c) uVar.K.get());
            case 125:
                return new FolderLogger((EventLogger) uVar.l0.get());
            case 126:
                return new q(this);
            case 127:
                return new com.quizlet.quizletandroid.config.c(new com.quizlet.quizletandroid.config.d(com.quizlet.generated.deeplinkpaths.a.c, 0));
            case 128:
                return new com.quizlet.quizletandroid.config.b(new com.quizlet.data.interactor.achievements.f(com.quizlet.generated.deeplinkpaths.a.b));
            case 129:
                return new com.quizlet.quizletandroid.config.a(new com.quizlet.data.interactor.achievements.f(com.quizlet.generated.deeplinkpaths.a.a));
            case 130:
                return new com.quizlet.local.cache.a(0);
            case 131:
                Context context11 = uVar.q();
                Intrinsics.checkNotNullParameter(context11, "context");
                kotlin.reflect.n[] nVarArr5 = com.quizlet.local.datastore.models.flashcards.b.a;
                Intrinsics.checkNotNullParameter(context11, "<this>");
                return (InterfaceC1076h) com.quizlet.local.datastore.models.flashcards.b.b.a(context11, com.quizlet.local.datastore.models.flashcards.b.a[0]);
            case 132:
                com.google.firebase.heartbeatinfo.e eVar4 = uVar.l;
                com.google.firebase.crashlytics.internal.metadata.p pVar = new com.google.firebase.crashlytics.internal.metadata.p(1);
                List list = Collections.EMPTY_LIST;
                if (list.contains("chapter")) {
                    throw new IllegalArgumentException("Labels must be unique.");
                }
                ArrayList arrayList = new ArrayList(list);
                arrayList.add("chapter");
                ArrayList arrayList2 = new ArrayList(list);
                arrayList2.add(Chapter.class);
                com.squareup.moshi.adapters.a aVarB = new com.squareup.moshi.adapters.a(TableOfContentItem.class, "tableOfContentsTypeLabel", arrayList, arrayList2).b(Section.class, "section").b(ExerciseGroup.class, "exerciseGroup");
                Intrinsics.checkNotNullExpressionValue(aVarB, "withSubtype(...)");
                pVar.a(aVarB);
                if (list.contains("created")) {
                    throw new IllegalArgumentException("Labels must be unique.");
                }
                ArrayList arrayList3 = new ArrayList(list);
                arrayList3.add("created");
                ArrayList arrayList4 = new ArrayList(list);
                arrayList4.add(ContentFolder.class);
                com.squareup.moshi.adapters.a aVarB2 = new com.squareup.moshi.adapters.a(CreatedFolder.class, "folderTypeLabel", arrayList3, arrayList4).b(BasicCourseFolder.class, "basicCourse").b(FullCourseFolder.class, "fullCourse");
                Intrinsics.checkNotNullExpressionValue(aVarB2, "withSubtype(...)");
                pVar.a(aVarB2);
                if (list.contains("createdFolder")) {
                    throw new IllegalArgumentException("Labels must be unique.");
                }
                ArrayList arrayList5 = new ArrayList(list);
                arrayList5.add("createdFolder");
                ArrayList arrayList6 = new ArrayList(list);
                arrayList6.add(CreatedFolderStudyMaterial.class);
                com.squareup.moshi.adapters.a aVarB3 = new com.squareup.moshi.adapters.a(M1.class, DBImageRefFields.Names.MODEL_TYPE, arrayList5, arrayList6).b(DeletedFolderStudyMaterial.class, "deletedFolder").b(RecommendedStudyMaterial.class, "recommended");
                Intrinsics.checkNotNullExpressionValue(aVarB3, "withSubtype(...)");
                pVar.a(aVarB3);
                if (list.contains("EXPLANATION_QUESTION")) {
                    throw new IllegalArgumentException("Labels must be unique.");
                }
                ArrayList arrayList7 = new ArrayList(list);
                arrayList7.add("EXPLANATION_QUESTION");
                ArrayList arrayList8 = new ArrayList(list);
                arrayList8.add(StudyMaterialItem$ExplanationQuestionItem.class);
                com.squareup.moshi.adapters.a aVarB4 = new com.squareup.moshi.adapters.a(N1.class, "studyMaterialItemTypeLabel", arrayList7, arrayList8).b(StudyMaterialItem$FlashcardSetItem.class, "SET").b(StudyMaterialItem$FolderItem.class, "FOLDER").b(StudyMaterialItem$NoteItem.class, "NOTE").b(StudyMaterialItem$TextbookItem.class, "TEXTBOOK").b(StudyMaterialItem$TextbookExerciseItem.class, "TEXTBOOK_EXERCISE");
                Intrinsics.checkNotNullExpressionValue(aVarB4, "withSubtype(...)");
                pVar.a(aVarB4);
                com.squareup.moshi.D d = new com.squareup.moshi.D(pVar);
                Intrinsics.checkNotNullExpressionValue(d, "build(...)");
                return d;
            case 133:
                return new C4633r(this, i6);
            case 134:
                return new com.quizlet.quizletandroid.lib.a(uVar.q());
            case 135:
                return new C4633r(this, i5);
            case 136:
                com.squareup.moshi.D moshi = (com.squareup.moshi.D) uVar.U1.get();
                Intrinsics.checkNotNullParameter(moshi, "moshi");
                moshi.getClass();
                com.squareup.moshi.l lVarA = moshi.a(QuestionCompatibility.class, com.squareup.moshi.internal.b.a, null);
                Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
                return lVarA;
            case 137:
                com.squareup.moshi.D d2 = new com.squareup.moshi.D(new com.google.firebase.crashlytics.internal.metadata.p(1));
                Intrinsics.checkNotNullExpressionValue(d2, "build(...)");
                return d2;
            case 138:
                return new s(this);
            case 139:
                return new C4633r(this, i3);
            case 140:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar5 = uVar.f;
                com.quizlet.quizletandroid.audio.core.a player = (com.quizlet.quizletandroid.audio.core.a) uVar.Y1.get();
                Intrinsics.checkNotNullParameter(player, "player");
                return new com.quizlet.quizletandroid.audio.players.c(player);
            case ModuleDescriptor.MODULE_VERSION /* 141 */:
                return new com.quizlet.quizletandroid.audio.core.a(new com.google.mlkit.common.sdkinternal.b(i4));
            case 142:
                com.quizlet.shared.usecase.folderstudymaterials.a aVar6 = uVar.f;
                com.quizlet.quizletandroid.managers.audio.g store = (com.quizlet.quizletandroid.managers.audio.g) uVar.d0.get();
                com.quizlet.quizletandroid.audio.players.h player2 = (com.quizlet.quizletandroid.audio.players.h) uVar.e0.get();
                Intrinsics.checkNotNullParameter(store, "store");
                Intrinsics.checkNotNullParameter(player2, "player");
                return new com.quizlet.quizletandroid.managers.audio.h(store, player2);
            default:
                throw new AssertionError(i7);
        }
    }
}
