package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import android.view.View;
import androidx.compose.ui.text.input.C;
import androidx.recyclerview.widget.RecyclerView;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.measurement.internal.Z;
import com.google.firebase.perf.metrics.AppStartTrace;
import com.google.firebase.perf.util.Timer;
import com.google.firebase.perf.v1.B;
import com.google.firebase.perf.v1.E;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.UpdateBuilder;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.perimeterx.mobile_sdk.PerimeterXChallengeResult;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentity;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSessionFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.edgy.ui.fragment.EdgyAddSchoolAndCoursesFragment;
import com.quizlet.eventlogger.EventLogBuilder;
import com.quizlet.eventlogger.EventLogUploader;
import com.quizlet.eventlogger.model.EventLog;
import com.quizlet.explanations.solution.fragments.ExplanationsSolutionFragment;
import com.quizlet.generated.enums.G1;
import com.quizlet.generated.enums.O1;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.view.MatchCardView;
import com.quizlet.studiablemodels.StudiableCheckpoint;
import com.quizlet.studiablemodels.StudiableStep;
import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicMarkableReference;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;
import retrofit2.K;

/* loaded from: classes2.dex */
public final /* synthetic */ class i implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ i(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        StringBuilder sb;
        com.quizlet.edgy.databinding.b bVar;
        int i = 18;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar = null;
        boolean zEquals = false;
        int i2 = 1;
        switch (this.a) {
            case 0:
                ((m) this.c).c((String) this.b, Boolean.FALSE);
                return;
            case 1:
                q qVar = (q) this.c;
                String str = (String) this.b;
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = qVar.g.d;
                dVar.getClass();
                String strA = com.google.firebase.crashlytics.internal.metadata.e.a(1024, str);
                synchronized (((AtomicMarkableReference) dVar.g)) {
                    try {
                        String str2 = (String) ((AtomicMarkableReference) dVar.g).getReference();
                        if (strA != null) {
                            zEquals = strA.equals(str2);
                        } else if (str2 == null) {
                            zEquals = true;
                        }
                        if (zEquals) {
                            return;
                        }
                        ((AtomicMarkableReference) dVar.g).set(strA, true);
                        ((com.google.firebase.crashlytics.internal.concurrency.d) dVar.c).b.a(new C(dVar, 29));
                        return;
                    } finally {
                    }
                }
            case 2:
                m mVar = ((q) this.c).g;
                Thread threadCurrentThread = Thread.currentThread();
                mVar.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                s sVar = mVar.n;
                if (sVar == null || !sVar.e.get()) {
                    long j = jCurrentTimeMillis / 1000;
                    String strE = mVar.e();
                    if (strE == null) {
                        Log.w("FirebaseCrashlytics", "Tried to write a non-fatal exception while no session was open.", null);
                        return;
                    }
                    com.google.firebase.crashlytics.internal.metadata.c cVar = new com.google.firebase.crashlytics.internal.metadata.c(j, strE, Collections.EMPTY_MAP);
                    com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = mVar.m;
                    dVar2.getClass();
                    Log.isLoggable("FirebaseCrashlytics", 2);
                    dVar2.l((Throwable) this.b, threadCurrentThread, "error", cVar, false);
                    return;
                }
                return;
            case 3:
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar3 = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.c;
                ((com.google.firebase.crashlytics.internal.metadata.h) dVar3.a).i((String) dVar3.b, (List) this.b);
                return;
            case 4:
                com.google.firebase.crashlytics.internal.send.c cVar2 = (com.google.firebase.crashlytics.internal.send.c) this.c;
                cVar2.getClass();
                try {
                    com.google.android.datatransport.runtime.q.a().d.a(cVar2.h.a.b(com.google.android.datatransport.d.c), 1);
                } catch (Exception unused) {
                }
                ((CountDownLatch) this.b).countDown();
                return;
            case 5:
                com.google.android.gms.tasks.f fVar2 = (com.google.android.gms.tasks.f) this.b;
                try {
                    fVar2.b(((com.google.firebase.messaging.n) this.c).a());
                    return;
                } catch (Exception e) {
                    fVar2.a(e);
                    return;
                }
            case 6:
                com.google.firebase.perf.config.v vVar = (com.google.firebase.perf.config.v) this.c;
                Context context = (Context) this.b;
                if (vVar.a != null || context == null) {
                    return;
                }
                vVar.a = context.getSharedPreferences("FirebasePerfSharedPrefs", 0);
                return;
            case 7:
                Timer timer = AppStartTrace.v;
                AppStartTrace appStartTrace = (AppStartTrace) this.c;
                appStartTrace.getClass();
                appStartTrace.b.c((E) ((B) this.b).h(), com.google.firebase.perf.v1.i.FOREGROUND_BACKGROUND);
                return;
            case 8:
                com.google.firebase.perf.transport.f fVar3 = (com.google.firebase.perf.transport.f) this.c;
                fVar3.getClass();
                com.google.firebase.perf.transport.b bVar2 = (com.google.firebase.perf.transport.b) this.b;
                fVar3.d(bVar2.a, bVar2.b);
                return;
            case 9:
                Context context2 = (Context) this.c;
                JSONObject jSONObject = (JSONObject) this.b;
                OTLogger.c("GoogleAdInfo", 4, "Getting AdvertisingIdClient info in BG thread");
                try {
                    boolean z = com.google.android.gms.ads.identifier.b.a(context2).b;
                    SharedPreferences sharedPreferences = context2.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
                    if (new com.onetrust.otpublishers.headless.Internal.profile.c(context2).t()) {
                        fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context2, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
                        zEquals = true;
                    }
                    String string = (zEquals ? fVar : sharedPreferences).getString("OT_IS_LIMIT_AD_TRACKING_ENABLED", "");
                    if (com.onetrust.otpublishers.headless.Internal.a.j(string)) {
                        String string2 = Boolean.toString(z);
                        if (zEquals) {
                            sharedPreferences = fVar;
                        }
                        sharedPreferences.edit().putString("OT_IS_LIMIT_AD_TRACKING_ENABLED", string2).apply();
                        sb = new StringBuilder("Saving Google Ad isLimitAdTrackingEnabled, value = ");
                        sb.append(z);
                    } else {
                        if (Boolean.parseBoolean(string) == z) {
                            OTLogger.c("GoogleAdInfo", 4, "Google Ad isLimitAdTrackingEnabled status not changed.");
                            return;
                        }
                        String string3 = Boolean.toString(z);
                        if (zEquals) {
                            sharedPreferences = fVar;
                        }
                        sharedPreferences.edit().putString("OT_IS_LIMIT_AD_TRACKING_ENABLED", string3).apply();
                        sb = new StringBuilder("Updating Google Ad isLimitAdTrackingEnabled, value = ");
                        sb.append(z);
                    }
                    OTLogger.c("GoogleAdInfo", 4, sb.toString());
                    com.quizlet.shared.usecase.studiableMetadata.a.d(context2, jSONObject, z);
                    return;
                } catch (Exception e2) {
                    Z.n("Error on saveAndConsentLogGooglePermissionState. Error = ", e2, "GoogleAdInfo", 6);
                    return;
                }
            case 10:
                K k = (K) this.b;
                com.onetrust.otpublishers.headless.UI.TVUI.fragments.p pVar = (com.onetrust.otpublishers.headless.UI.TVUI.fragments.p) ((com.quizlet.data.repository.school.membership.a) this.c).b;
                try {
                    if (k.b != null) {
                        pVar.x.b = pVar.G(com.onetrust.otpublishers.headless.UI.TVUI.datautils.e.a(), new JSONObject((String) k.b));
                        pVar.E = 1;
                        return;
                    }
                    return;
                } catch (Exception e3) {
                    Z.n("Error while fetching IAB Vendor Disclosure details:  ", e3, "TV Vendor", 6);
                    return;
                }
            case 11:
                com.perimeterx.mobile_sdk.doctor_app.d dVar4 = (com.perimeterx.mobile_sdk.doctor_app.d) this.b;
                androidx.constraintlayout.core.widgets.analyzer.f fVar4 = (androidx.constraintlayout.core.widgets.analyzer.f) this.c;
                fVar4.getClass();
                PXDoctorActivity pXDoctorActivity = PXDoctorActivity.f;
                if (pXDoctorActivity == null) {
                    dVar4.invoke();
                    return;
                } else {
                    fVar4.b = true;
                    pXDoctorActivity.q(false, new com.braze.triggers.managers.h(10, fVar4, dVar4));
                    return;
                }
            case 12:
                ((androidx.constraintlayout.core.widgets.analyzer.f) this.c).e((Function0) this.b);
                return;
            case 13:
                com.google.android.gms.internal.mlkit_common.u uVar = PXDoctorActivity.e;
                ((View) this.c).setAlpha(1.0f);
                ((PXDoctorActivity) this.b).q(true, null);
                return;
            case 14:
                ((java.util.Timer) this.c).schedule(new com.facebook.appevents.codeless.j((com.perimeterx.mobile_sdk.session.d) this.b, i2), 5000L);
                return;
            case 15:
                if (((com.perimeterx.mobile_sdk.session.d) this.c).a != null) {
                    com.perimeterx.mobile_sdk.session.d sessionManagerProtocol = (com.perimeterx.mobile_sdk.session.d) this.b;
                    Intrinsics.checkNotNullParameter(sessionManagerProtocol, "sessionManagerProtocol");
                    com.perimeterx.mobile_sdk.session.l.d.b();
                    return;
                }
                return;
            case 16:
                Function1 function1 = (Function1) this.c;
                if (function1 != null) {
                    if (Intrinsics.b((Boolean) this.b, Boolean.TRUE)) {
                        function1.invoke(PerimeterXChallengeResult.SOLVED);
                        return;
                    } else {
                        function1.invoke(PerimeterXChallengeResult.CANCELLED);
                        return;
                    }
                }
                return;
            case 17:
                ExecutionRouter.a((ExecutionRouter) this.c, (Callable) this.b);
                return;
            case 18:
                String str3 = EdgyAddSchoolAndCoursesFragment.u;
                if (((ArrayList) this.c).isEmpty() || (bVar = (com.quizlet.edgy.databinding.b) ((EdgyAddSchoolAndCoursesFragment) this.b).d) == null) {
                    return;
                }
                bVar.e.k0(0);
                return;
            case 19:
                EventLogBuilder.a((EventLogBuilder) this.c, (EventLog) this.b);
                return;
            case 20:
                EventLogUploader.a((EventLogUploader) this.c, (io.reactivex.rxjava3.subjects.p) this.b);
                return;
            case 21:
                String str4 = ExplanationsSolutionFragment.s;
                if (((com.quizlet.explanations.solution.viewmodel.e) this.c).b) {
                    ExplanationsSolutionFragment explanationsSolutionFragment = (ExplanationsSolutionFragment) this.b;
                    RecyclerView solutionsList = ((com.quizlet.explanations.databinding.h) explanationsSolutionFragment.J()).c;
                    Intrinsics.checkNotNullExpressionValue(solutionsList, "solutionsList");
                    solutionsList.postDelayed(new com.google.android.gms.common.api.internal.w(explanationsSolutionFragment, i), 300L);
                    return;
                }
                return;
            case EventType.WINDOW_STATE /* 22 */:
                com.quizlet.infra.legacysyncengine.net.request.b bVar3 = (com.quizlet.infra.legacysyncengine.net.request.b) this.c;
                bVar3.getClass();
                ModelIdentityCollection modelIdentityCollection = new ModelIdentityCollection();
                ModelIdentityCollection modelIdentityCollection2 = new ModelIdentityCollection();
                for (DBModel dBModel : (List) this.b) {
                    ModelIdentity identity = dBModel.getIdentity();
                    modelIdentityCollection.add(identity);
                    if (dBModel.getDeleted()) {
                        modelIdentityCollection2.add(identity);
                    }
                }
                try {
                    int size = modelIdentityCollection.size();
                    DatabaseHelper databaseHelper = bVar3.i;
                    ModelType modelType = bVar3.f;
                    if (size > 0) {
                        UpdateBuilder updateBuilder = databaseHelper.j(modelType).updateBuilder();
                        updateBuilder.updateColumnValue("dirty", Boolean.FALSE);
                        modelIdentityCollection.whereIn(updateBuilder.where());
                        updateBuilder.update();
                    }
                    if (modelIdentityCollection2.size() > 0) {
                        UpdateBuilder updateBuilder2 = databaseHelper.j(modelType).updateBuilder();
                        updateBuilder2.updateColumnValue("isDeleted", Boolean.TRUE);
                        modelIdentityCollection2.whereIn(updateBuilder2.where());
                        updateBuilder2.update();
                        return;
                    }
                    return;
                } catch (SQLException e4) {
                    timber.log.c.a(e4);
                    return;
                }
            case EventType.AUDIO /* 23 */:
                List list = G.D1;
                ((G) this.c).Z((StudiableCheckpoint) ((StudiableStep) this.b));
                return;
            case EventType.VIDEO /* 24 */:
                String str5 = EditSetFragment.J;
                EditSetFragment editSetFragment = (EditSetFragment) this.c;
                if (editSetFragment.isAdded()) {
                    editSetFragment.W(editSetFragment.G.b, (O1) this.b);
                    return;
                }
                return;
            case EventType.SUBS /* 25 */:
                Zh zh = (Zh) this.c;
                DeleteBuilder deleteBuilder = ((DatabaseHelper) zh.e).j(Models.SESSION).deleteBuilder();
                deleteBuilder.where().eq(DBSessionFields.STUDYABLE.getDatabaseColumnName(), (Serializable) this.b).and().eq(DBSessionFields.ITEM_TYPE.getDatabaseColumnName(), Integer.valueOf(G1.SET.b()));
                timber.log.c.a.a("Deleted %d sessions", Integer.valueOf(deleteBuilder.delete()));
                ((ExecutionRouter) zh.d).g(new com.google.firebase.crashlytics.internal.metadata.q(zh, i));
                return;
            case EventType.CDN /* 26 */:
                ((com.quizlet.quizletandroid.ui.setcreation.viewholders.l) this.c).a((String) this.b, null, null);
                return;
            case 27:
                String str6 = MatchActivity.s;
                ((MatchActivity) this.c).c0().removeView((com.quizlet.quizletandroid.ui.studymodes.match.view.a) this.b);
                return;
            case 28:
                MatchCardView.a((MatchCardView) this.c, (io.reactivex.rxjava3.subjects.f) this.b);
                return;
            default:
                ((com.quizlet.data.interactor.school.e) this.c).a = 0L;
                ((com.quizlet.quizletandroid.ui.studymodes.write.f) this.b).run();
                return;
        }
    }

    public /* synthetic */ i(q qVar, Throwable th) {
        this.a = 2;
        Map map = Collections.EMPTY_MAP;
        this.c = qVar;
        this.b = th;
    }

    public /* synthetic */ i(com.quizlet.shared.usecase.studiableMetadata.a aVar, Context context, JSONObject jSONObject) {
        this.a = 9;
        this.c = context;
        this.b = jSONObject;
    }
}
