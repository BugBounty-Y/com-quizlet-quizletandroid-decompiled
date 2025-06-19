package androidx.work.impl.utils;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.T;
import androidx.work.impl.WorkDatabase;
import com.android.billingclient.api.C1473b;
import com.facebook.AccessToken;
import com.facebook.B;
import com.facebook.Profile;
import com.facebook.internal.J;
import com.facebook.z;
import com.google.android.gms.internal.ads.RunnableC1788Vd;
import com.google.android.gms.internal.mlkit_vision_common.D;
import com.google.firebase.messaging.FirebaseMessaging;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws SQLException {
        AccessToken accessTokenB;
        Profile profile;
        AccessToken accessTokenC;
        String string;
        FileInputStream fileInputStreamOpenFileInput;
        boolean z = true;
        FileInputStream fileInputStream = null;
        com.google.firebase.remoteconfig.internal.c cVarA = null;
        switch (this.a) {
            case 0:
                WorkDatabase workDatabase = (WorkDatabase) ((com.google.android.gms.internal.instantapps.a) this.b).b;
                Long lP = workDatabase.l().p("next_alarm_manager_id");
                int iLongValue = lP != null ? (int) lP.longValue() : 0;
                workDatabase.l().t(new androidx.work.impl.model.d(Long.valueOf(iLongValue != Integer.MAX_VALUE ? iLongValue + 1 : 0), "next_alarm_manager_id"));
                return Integer.valueOf(iLongValue);
            case 1:
                return (AssetFileDescriptor) this.b;
            case 2:
                return com.airbnb.lottie.l.d((ByteArrayInputStream) this.b, null);
            case 3:
                com.google.android.material.search.a aVar = (com.google.android.material.search.a) this.b;
                com.facebook.o oVar = com.facebook.o.a;
                com.facebook.f fVarO = com.facebook.f.f.o();
                SharedPreferences sharedPreferences = fVarO.b.a;
                if (!sharedPreferences.contains("com.facebook.AccessTokenManager.CachedAccessToken") || (string = sharedPreferences.getString("com.facebook.AccessTokenManager.CachedAccessToken", null)) == null) {
                    accessTokenB = null;
                } else {
                    try {
                        JSONObject jSONObject = new JSONObject(string);
                        Date date = AccessToken.l;
                        accessTokenB = D.b(jSONObject);
                    } catch (JSONException unused) {
                    }
                }
                if (accessTokenB != null) {
                    fVarO.c(accessTokenB, false);
                }
                com.google.android.material.shape.e eVar = com.facebook.h.f;
                com.facebook.h hVarU = eVar.u();
                String string2 = ((z) hVarU.b).a.getString("com.facebook.ProfileManager.CachedProfile", null);
                if (string2 != null) {
                    try {
                        profile = new Profile(new JSONObject(string2));
                    } catch (JSONException unused2) {
                    }
                } else {
                    profile = null;
                }
                if (profile != null) {
                    hVarU.a(profile, false);
                }
                Date date2 = AccessToken.l;
                if (D.d() && ((Profile) eVar.u().c) == null && (accessTokenC = D.c()) != null) {
                    if (D.d()) {
                        J.q(new com.google.android.gms.internal.mlkit_common.u(8), accessTokenC.e);
                    } else {
                        eVar.u().a(null, true);
                    }
                }
                if (aVar != null) {
                    ((Function0) aVar.b).invoke();
                }
                Context context = com.facebook.o.a();
                String str = com.facebook.o.d;
                Intrinsics.checkNotNullParameter(context, "context");
                String str2 = com.facebook.appevents.j.c;
                Intrinsics.checkNotNullParameter(context, "context");
                if (B.c()) {
                    com.facebook.appevents.j jVar = new com.facebook.appevents.j(context, str);
                    ScheduledThreadPoolExecutor scheduledThreadPoolExecutorB = com.facebook.appevents.j.b();
                    if (scheduledThreadPoolExecutorB == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    scheduledThreadPoolExecutorB.execute(new androidx.credentials.playservices.controllers.c(17, context, jVar));
                }
                if (!com.facebook.internal.instrument.crashshield.a.b(B.class)) {
                    try {
                        Context contextA = com.facebook.o.a();
                        ApplicationInfo applicationInfo = contextA.getPackageManager().getApplicationInfo(contextA.getPackageName(), 128);
                        Intrinsics.checkNotNullExpressionValue(applicationInfo, "ctx.packageManager.getAp…ageManager.GET_META_DATA)");
                        Bundle bundle = applicationInfo.metaData;
                        if (bundle != null && bundle.getBoolean("com.facebook.sdk.AutoAppLinkEnabled", false)) {
                            com.facebook.appevents.p pVar = new com.facebook.appevents.p(contextA);
                            Bundle bundle2 = new Bundle();
                            if (!J.z()) {
                                bundle2.putString("SchemeWarning", "You haven't set the Auto App Link URL scheme: fb<YOUR APP ID> in AndroidManifest");
                                Log.w("com.facebook.B", "You haven't set the Auto App Link URL scheme: fb<YOUR APP ID> in AndroidManifest");
                            }
                            if (B.c()) {
                                pVar.a.d(bundle2, "fb_auto_applink");
                            }
                        }
                    } catch (PackageManager.NameNotFoundException unused3) {
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(B.class, th);
                    }
                }
                Context context2 = com.facebook.o.a().getApplicationContext();
                Intrinsics.checkNotNullExpressionValue(context2, "getApplicationContext().applicationContext");
                Intrinsics.checkNotNullParameter(context2, "context");
                com.facebook.appevents.j jVar2 = new com.facebook.appevents.j(context2, (String) null);
                if (!com.facebook.internal.instrument.crashshield.a.b(jVar2)) {
                    try {
                        com.facebook.appevents.h.c(com.facebook.appevents.n.a);
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(jVar2, th2);
                    }
                }
                return null;
            case 4:
                com.google.firebase.crashlytics.internal.common.m mVar = ((com.google.firebase.crashlytics.internal.common.q) this.b).g;
                mVar.getClass();
                com.google.firebase.crashlytics.internal.concurrency.d.a();
                com.quizlet.data.repository.activitycenter.b bVar = mVar.c;
                String str3 = (String) bVar.b;
                com.google.firebase.crashlytics.internal.persistence.c cVar = (com.google.firebase.crashlytics.internal.persistence.c) bVar.c;
                cVar.getClass();
                if (new File(cVar.c, str3).exists()) {
                    Log.isLoggable("FirebaseCrashlytics", 2);
                    String str4 = (String) bVar.b;
                    cVar.getClass();
                    new File(cVar.c, str4).delete();
                } else {
                    String strE = mVar.e();
                    if (strE == null || !mVar.j.c(strE)) {
                        z = false;
                    }
                }
                return Boolean.valueOf(z);
            case 5:
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) ((com.quizlet.data.repository.qclass.c) this.b).c;
                com.google.firebase.crashlytics.internal.settings.d dVar = (com.google.firebase.crashlytics.internal.settings.d) sVar.c;
                androidx.emoji2.text.r rVar = (androidx.emoji2.text.r) sVar.g;
                rVar.getClass();
                com.google.firebase.crashlytics.internal.concurrency.d.b();
                try {
                    HashMap mapC = androidx.emoji2.text.r.c(dVar);
                    io.ktor.client.plugins.api.d dVar2 = new io.ktor.client.plugins.api.d(mapC, rVar.a);
                    dVar2.r("User-Agent", "Crashlytics Android SDK/19.4.3");
                    dVar2.r("X-CRASHLYTICS-DEVELOPER-TOKEN", "470fa2b4ae81cd56ecbcda9735803434cec591fa");
                    androidx.emoji2.text.r.b(dVar2, dVar);
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    mapC.toString();
                    Log.isLoggable("FirebaseCrashlytics", 2);
                    return rVar.e(dVar2.l());
                } catch (IOException e) {
                    Log.e("FirebaseCrashlytics", "Settings request failed.", e);
                    return null;
                }
            case 6:
                return ((com.google.firebase.remoteconfig.f) this.b).b("firebase");
            case 7:
                com.google.firebase.remoteconfig.internal.k kVar = (com.google.firebase.remoteconfig.internal.k) this.b;
                synchronized (kVar) {
                    try {
                        fileInputStreamOpenFileInput = kVar.a.openFileInput(kVar.b);
                    } catch (FileNotFoundException | JSONException unused4) {
                        fileInputStreamOpenFileInput = null;
                    } catch (Throwable th3) {
                        th = th3;
                    }
                    try {
                        int iAvailable = fileInputStreamOpenFileInput.available();
                        byte[] bArr = new byte[iAvailable];
                        fileInputStreamOpenFileInput.read(bArr, 0, iAvailable);
                        cVarA = com.google.firebase.remoteconfig.internal.c.a(new JSONObject(new String(bArr, "UTF-8")));
                        fileInputStreamOpenFileInput.close();
                    } catch (FileNotFoundException | JSONException unused5) {
                        if (fileInputStreamOpenFileInput != null) {
                            fileInputStreamOpenFileInput.close();
                        }
                        return cVarA;
                    } catch (Throwable th4) {
                        th = th4;
                        fileInputStream = fileInputStreamOpenFileInput;
                        if (fileInputStream != null) {
                            fileInputStream.close();
                        }
                        throw th;
                    }
                }
                return cVarA;
            case 8:
                com.quizlet.billing.manager.f fVar = (com.quizlet.billing.manager.f) this.b;
                C1473b c1473b = fVar.e;
                if (c1473b != null) {
                    c1473b.h(fVar);
                    return io.reactivex.rxjava3.internal.operators.completable.f.a;
                }
                Intrinsics.m("billingClient");
                throw null;
            case 9:
                DatabaseHelper.d((DatabaseHelper) this.b);
                return null;
            case 10:
                return Boolean.valueOf(((com.quizlet.featuregate.contracts.features.a) this.b).isEnabled());
            case 11:
                com.quizlet.data.repository.widget.b bVar2 = (com.quizlet.data.repository.widget.b) this.b;
                try {
                    ((FirebaseMessaging) bVar2.b).deleteToken();
                    return ((FirebaseMessaging) bVar2.b).getToken();
                } catch (IOException e2) {
                    timber.log.c.a.p(e2);
                    return Unit.a;
                }
            case 12:
                RunnableC1788Vd runnableC1788Vd = (RunnableC1788Vd) this.b;
                ((DatabaseHelper) runnableC1788Vd.c).q((List) runnableC1788Vd.b);
                T t = (T) runnableC1788Vd.f;
                if (t != null) {
                    ((ExecutionRouter) runnableC1788Vd.e).g(new com.google.firebase.crashlytics.internal.metadata.q(t, 12));
                }
                return null;
            case 13:
                return Long.valueOf(((com.quizlet.quizletandroid.managers.audio.g) this.b).b.d());
            default:
                return Long.valueOf(((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) this.b).b.d());
        }
    }
}
