package com.facebook.internal;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.compose.animation.d0;
import com.facebook.FacebookException;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.C1548c;
import com.google.android.gms.internal.mlkit_vision_common.I;
import java.util.Arrays;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class t implements Runnable {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Context b;
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;

    public /* synthetic */ t(Context context, String str, String str2) {
        this.b = context;
        this.c = str;
        this.d = str2;
    }

    @Override // java.lang.Runnable
    public final void run() throws JSONException, NumberFormatException {
        JSONObject jSONObject;
        final int i = 1;
        final int i2 = 0;
        switch (this.a) {
            case 0:
                String applicationId = this.c;
                Intrinsics.checkNotNullParameter(applicationId, "$applicationId");
                Context context = this.b;
                Intrinsics.checkNotNullParameter(context, "$context");
                String gateKeepersKey = this.d;
                Intrinsics.checkNotNullParameter(gateKeepersKey, "$gateKeepersKey");
                JSONObject jSONObjectA = u.a();
                if (jSONObjectA.length() != 0) {
                    u.d(applicationId, jSONObjectA);
                    context.getSharedPreferences("com.facebook.internal.preferences.APP_GATEKEEPERS", 0).edit().putString(gateKeepersKey, jSONObjectA.toString()).apply();
                    u.d = Long.valueOf(System.currentTimeMillis());
                }
                u.e();
                u.a.set(false);
                return;
            default:
                Context context2 = this.b;
                String settingsKey = this.c;
                String applicationId2 = this.d;
                Intrinsics.checkNotNullParameter(context2, "$context");
                Intrinsics.checkNotNullParameter(settingsKey, "$settingsKey");
                Intrinsics.checkNotNullParameter(applicationId2, "$applicationId");
                SharedPreferences sharedPreferences = context2.getSharedPreferences("com.facebook.internal.preferences.APP_SETTINGS", 0);
                v vVarE = null;
                String string = sharedPreferences.getString(settingsKey, null);
                boolean zD = J.D(string);
                y yVar = y.a;
                if (!zD) {
                    if (string == null) {
                        throw new IllegalStateException("Required value was null.");
                    }
                    try {
                        jSONObject = new JSONObject(string);
                    } catch (JSONException unused) {
                        com.facebook.o oVar = com.facebook.o.a;
                        jSONObject = null;
                    }
                    if (jSONObject != null) {
                        vVarE = y.e(applicationId2, jSONObject);
                    }
                }
                JSONObject jSONObjectA2 = y.a();
                y.e(applicationId2, jSONObjectA2);
                sharedPreferences.edit().putString(settingsKey, jSONObjectA2.toString()).apply();
                if (vVarE != null) {
                    String str = vVarE.i;
                    if (!y.f && str != null && str.length() > 0) {
                        y.f = true;
                        Log.w("y", str);
                    }
                }
                AtomicBoolean atomicBoolean = u.a;
                Intrinsics.checkNotNullParameter(applicationId2, "applicationId");
                JSONObject jSONObjectA3 = u.a();
                com.facebook.o.a().getSharedPreferences("com.facebook.internal.preferences.APP_GATEKEEPERS", 0).edit().putString(d0.s(new Object[]{applicationId2}, 1, "com.facebook.internal.APP_GATEKEEPERS.%s", "format(format, *args)"), jSONObjectA3.toString()).apply();
                u.d(applicationId2, jSONObjectA3);
                com.facebook.appevents.p pVar = com.facebook.appevents.internal.j.a;
                Context contextA = com.facebook.o.a();
                final String applicationId3 = com.facebook.o.b();
                if (com.facebook.B.c()) {
                    if (contextA instanceof Application) {
                        Application context3 = (Application) contextA;
                        Intrinsics.checkNotNullParameter(context3, "application");
                        String str2 = com.facebook.appevents.j.c;
                        Intrinsics.checkNotNullParameter(context3, "application");
                        if (!com.facebook.o.o.get()) {
                            throw new FacebookException("The Facebook sdk must be initialized before calling activateApp");
                        }
                        if (!com.facebook.appevents.c.c) {
                            if (com.facebook.appevents.j.b() == null) {
                                com.google.firebase.perf.logging.b.j();
                            }
                            ScheduledThreadPoolExecutor scheduledThreadPoolExecutorB = com.facebook.appevents.j.b();
                            if (scheduledThreadPoolExecutorB == null) {
                                throw new IllegalStateException("Required value was null.");
                            }
                            scheduledThreadPoolExecutorB.execute(new RunnableC0131h(4));
                        }
                        com.facebook.appevents.w wVar = com.facebook.appevents.w.a;
                        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.w.class)) {
                            try {
                                if (!com.facebook.appevents.w.c.get()) {
                                    com.facebook.appevents.w.a.b();
                                }
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.w.class, th);
                            }
                        }
                        if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.o.class)) {
                            try {
                                Intrinsics.checkNotNullParameter(context3, "context");
                                Intrinsics.checkNotNullParameter(applicationId3, "applicationId");
                                final Context applicationContext = context3.getApplicationContext();
                                if (applicationContext != null) {
                                    if (!u.b("app_events_killswitch", com.facebook.o.b(), false)) {
                                        com.facebook.o.c().execute(new Runnable() { // from class: com.facebook.n
                                            @Override // java.lang.Runnable
                                            public final void run() {
                                                com.facebook.appevents.ondeviceprocessing.e eVar = com.facebook.appevents.ondeviceprocessing.e.a;
                                                String applicationId4 = applicationId3;
                                                Context applicationContext2 = applicationContext;
                                                switch (i2) {
                                                    case 0:
                                                        o oVar2 = o.a;
                                                        Intrinsics.checkNotNullParameter(applicationContext2, "$applicationContext");
                                                        Intrinsics.checkNotNullParameter(applicationId4, "$applicationId");
                                                        o oVar3 = o.a;
                                                        if (com.facebook.internal.instrument.crashshield.a.b(oVar3)) {
                                                            return;
                                                        }
                                                        try {
                                                            C1548c c1548cB = AbstractC1554i.b(applicationContext2);
                                                            SharedPreferences sharedPreferences2 = applicationContext2.getSharedPreferences("com.facebook.sdk.attributionTracking", 0);
                                                            String strConcat = applicationId4.concat("ping");
                                                            long j = sharedPreferences2.getLong(strConcat, 0L);
                                                            try {
                                                                JSONObject jSONObjectA4 = com.facebook.appevents.internal.f.a(com.facebook.appevents.internal.e.a, c1548cB, I.a(applicationContext2), o.f(applicationContext2), applicationContext2);
                                                                String str3 = com.facebook.appevents.j.c;
                                                                String strI = com.google.firebase.perf.logging.b.i();
                                                                if (strI != null) {
                                                                    jSONObjectA4.put("install_referrer", strI);
                                                                }
                                                                String str4 = String.format("%s/activities", Arrays.copyOf(new Object[]{applicationId4}, 1));
                                                                Intrinsics.checkNotNullExpressionValue(str4, "format(format, *args)");
                                                                o.r.getClass();
                                                                String str5 = t.j;
                                                                t tVarR = assistantMode.utils.studiableMetadata.b.R(null, str4, jSONObjectA4, null);
                                                                if (j == 0 && tVarR.c().c == null) {
                                                                    SharedPreferences.Editor editorEdit = sharedPreferences2.edit();
                                                                    editorEdit.putLong(strConcat, System.currentTimeMillis());
                                                                    editorEdit.apply();
                                                                    com.google.mlkit.common.sdkinternal.model.a aVar = com.facebook.internal.A.c;
                                                                    y yVar2 = y.d;
                                                                    Intrinsics.checkNotNullExpressionValue("com.facebook.o", "TAG");
                                                                    com.google.mlkit.common.sdkinternal.model.a.v(yVar2, "com.facebook.o", "MOBILE_APP_INSTALL has been logged");
                                                                    return;
                                                                }
                                                                return;
                                                            } catch (JSONException e) {
                                                                throw new FacebookException("An error occurred while publishing install.", e);
                                                            }
                                                        } catch (Exception unused2) {
                                                            return;
                                                        } catch (Throwable th2) {
                                                            com.facebook.internal.instrument.crashshield.a.a(oVar3, th2);
                                                            return;
                                                        }
                                                    default:
                                                        if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ondeviceprocessing.a.class)) {
                                                            return;
                                                        }
                                                        try {
                                                            Intrinsics.checkNotNullParameter(applicationContext2, "$context");
                                                            SharedPreferences sharedPreferences3 = applicationContext2.getSharedPreferences("com.facebook.sdk.attributionTracking", 0);
                                                            String strConcat2 = applicationId4.concat("pingForOnDevice");
                                                            if (sharedPreferences3.getLong(strConcat2, 0L) == 0) {
                                                                if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ondeviceprocessing.e.class)) {
                                                                    try {
                                                                        Intrinsics.checkNotNullParameter(applicationId4, "applicationId");
                                                                        eVar.b(com.facebook.appevents.ondeviceprocessing.c.MOBILE_APP_INSTALL, applicationId4, K.a);
                                                                    } catch (Throwable th3) {
                                                                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ondeviceprocessing.e.class, th3);
                                                                    }
                                                                }
                                                                SharedPreferences.Editor editorEdit2 = sharedPreferences3.edit();
                                                                editorEdit2.putLong(strConcat2, System.currentTimeMillis());
                                                                editorEdit2.apply();
                                                                return;
                                                            }
                                                            return;
                                                        } catch (Throwable th4) {
                                                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ondeviceprocessing.a.class, th4);
                                                            return;
                                                        }
                                                }
                                            }
                                        });
                                    }
                                    if (C1563s.b(EnumC1562q.OnDeviceEventProcessing) && com.facebook.appevents.ondeviceprocessing.a.a() && !com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ondeviceprocessing.a.class)) {
                                        try {
                                            final Context contextA2 = com.facebook.o.a();
                                            com.facebook.o.c().execute(new Runnable() { // from class: com.facebook.n
                                                @Override // java.lang.Runnable
                                                public final void run() {
                                                    com.facebook.appevents.ondeviceprocessing.e eVar = com.facebook.appevents.ondeviceprocessing.e.a;
                                                    String applicationId4 = applicationId3;
                                                    Context applicationContext2 = contextA2;
                                                    switch (i) {
                                                        case 0:
                                                            o oVar2 = o.a;
                                                            Intrinsics.checkNotNullParameter(applicationContext2, "$applicationContext");
                                                            Intrinsics.checkNotNullParameter(applicationId4, "$applicationId");
                                                            o oVar3 = o.a;
                                                            if (com.facebook.internal.instrument.crashshield.a.b(oVar3)) {
                                                                return;
                                                            }
                                                            try {
                                                                C1548c c1548cB = AbstractC1554i.b(applicationContext2);
                                                                SharedPreferences sharedPreferences2 = applicationContext2.getSharedPreferences("com.facebook.sdk.attributionTracking", 0);
                                                                String strConcat = applicationId4.concat("ping");
                                                                long j = sharedPreferences2.getLong(strConcat, 0L);
                                                                try {
                                                                    JSONObject jSONObjectA4 = com.facebook.appevents.internal.f.a(com.facebook.appevents.internal.e.a, c1548cB, I.a(applicationContext2), o.f(applicationContext2), applicationContext2);
                                                                    String str3 = com.facebook.appevents.j.c;
                                                                    String strI = com.google.firebase.perf.logging.b.i();
                                                                    if (strI != null) {
                                                                        jSONObjectA4.put("install_referrer", strI);
                                                                    }
                                                                    String str4 = String.format("%s/activities", Arrays.copyOf(new Object[]{applicationId4}, 1));
                                                                    Intrinsics.checkNotNullExpressionValue(str4, "format(format, *args)");
                                                                    o.r.getClass();
                                                                    String str5 = t.j;
                                                                    t tVarR = assistantMode.utils.studiableMetadata.b.R(null, str4, jSONObjectA4, null);
                                                                    if (j == 0 && tVarR.c().c == null) {
                                                                        SharedPreferences.Editor editorEdit = sharedPreferences2.edit();
                                                                        editorEdit.putLong(strConcat, System.currentTimeMillis());
                                                                        editorEdit.apply();
                                                                        com.google.mlkit.common.sdkinternal.model.a aVar = com.facebook.internal.A.c;
                                                                        y yVar2 = y.d;
                                                                        Intrinsics.checkNotNullExpressionValue("com.facebook.o", "TAG");
                                                                        com.google.mlkit.common.sdkinternal.model.a.v(yVar2, "com.facebook.o", "MOBILE_APP_INSTALL has been logged");
                                                                        return;
                                                                    }
                                                                    return;
                                                                } catch (JSONException e) {
                                                                    throw new FacebookException("An error occurred while publishing install.", e);
                                                                }
                                                            } catch (Exception unused2) {
                                                                return;
                                                            } catch (Throwable th2) {
                                                                com.facebook.internal.instrument.crashshield.a.a(oVar3, th2);
                                                                return;
                                                            }
                                                        default:
                                                            if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ondeviceprocessing.a.class)) {
                                                                return;
                                                            }
                                                            try {
                                                                Intrinsics.checkNotNullParameter(applicationContext2, "$context");
                                                                SharedPreferences sharedPreferences3 = applicationContext2.getSharedPreferences("com.facebook.sdk.attributionTracking", 0);
                                                                String strConcat2 = applicationId4.concat("pingForOnDevice");
                                                                if (sharedPreferences3.getLong(strConcat2, 0L) == 0) {
                                                                    if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ondeviceprocessing.e.class)) {
                                                                        try {
                                                                            Intrinsics.checkNotNullParameter(applicationId4, "applicationId");
                                                                            eVar.b(com.facebook.appevents.ondeviceprocessing.c.MOBILE_APP_INSTALL, applicationId4, K.a);
                                                                        } catch (Throwable th3) {
                                                                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ondeviceprocessing.e.class, th3);
                                                                        }
                                                                    }
                                                                    SharedPreferences.Editor editorEdit2 = sharedPreferences3.edit();
                                                                    editorEdit2.putLong(strConcat2, System.currentTimeMillis());
                                                                    editorEdit2.apply();
                                                                    return;
                                                                }
                                                                return;
                                                            } catch (Throwable th4) {
                                                                com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ondeviceprocessing.a.class, th4);
                                                                return;
                                                            }
                                                    }
                                                }
                                            });
                                        } catch (Throwable th2) {
                                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ondeviceprocessing.a.class, th2);
                                        }
                                    }
                                }
                            } catch (Throwable th3) {
                                com.facebook.internal.instrument.crashshield.a.a(com.facebook.o.class, th3);
                            }
                        }
                        com.facebook.appevents.internal.c.c(context3, applicationId3);
                        if (C1563s.b(EnumC1562q.GPSPACAProcessing)) {
                            com.facebook.appevents.gps.pa.b bVar = com.facebook.appevents.gps.pa.b.a;
                            if (!com.facebook.internal.instrument.crashshield.a.b(bVar)) {
                                try {
                                    if (!com.facebook.appevents.gps.pa.b.d) {
                                        com.facebook.appevents.gps.pa.b.a();
                                    }
                                    if (com.facebook.appevents.gps.pa.b.c) {
                                        bVar.b(applicationId3, "fb_mobile_app_install");
                                    }
                                } catch (Throwable th4) {
                                    com.facebook.internal.instrument.crashshield.a.a(bVar, th4);
                                }
                            }
                        }
                    } else {
                        Log.w("com.facebook.appevents.internal.j", "Automatic logging of basic events will not happen, because FacebookSdk.getApplicationContext() returns object that is not instance of android.app.Application. Make sure you call FacebookSdk.sdkInitialize() from Application class and pass application context.");
                    }
                }
                y.d.set(y.c.containsKey(applicationId2) ? x.c : x.d);
                yVar.j();
                return;
        }
    }

    public /* synthetic */ t(String str, Context context, String str2) {
        this.c = str;
        this.b = context;
        this.d = str2;
    }
}
