package com.facebook.appevents.gps.ara;

import android.adservices.measurement.MeasurementManager;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import androidx.credentials.i;
import com.facebook.appevents.e;
import com.facebook.o;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.n;
import kotlin.sequences.q;
import kotlin.text.StringsKt;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();
    public static final String b;
    public static boolean c;
    public static com.facebook.appevents.gps.a d;
    public static String e;

    static {
        String string = c.class.toString();
        Intrinsics.checkNotNullExpressionValue(string, "GpsAraTriggersManager::class.java.toString()");
        b = string;
    }

    public final boolean a() {
        String str = b;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return false;
        }
        try {
            if (!c) {
                return false;
            }
            try {
                Class.forName("android.adservices.measurement.MeasurementManager");
                return true;
            } catch (Error e2) {
                Log.i(str, "FAILURE_NO_MEASUREMENT_MANAGER_CLASS");
                com.facebook.appevents.gps.a aVar = d;
                if (aVar == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle = new Bundle();
                bundle.putString("gps_ara_failed_reason", e2.toString());
                Unit unit = Unit.a;
                aVar.a(bundle, "gps_ara_failed");
                return false;
            } catch (Exception e3) {
                Log.i(str, "FAILURE_NO_MEASUREMENT_MANAGER_CLASS");
                com.facebook.appevents.gps.a aVar2 = d;
                if (aVar2 == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle2 = new Bundle();
                bundle2.putString("gps_ara_failed_reason", e3.toString());
                Unit unit2 = Unit.a;
                aVar2.a(bundle2, "gps_ara_failed");
                return false;
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return false;
        }
    }

    public final String b(e eVar) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            JSONObject jSONObject = eVar.a;
            if (jSONObject != null && jSONObject.length() != 0) {
                Iterator<String> itKeys = jSONObject.keys();
                Intrinsics.checkNotNullExpressionValue(itKeys, "params.keys()");
                return q.g(q.i(n.b(itKeys), new androidx.credentials.playservices.controllers.BeginSignIn.c(jSONObject, 12)), "&");
            }
            return "";
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final void c(String applicationId, e event) {
        String str = b;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(applicationId, "applicationId");
            Intrinsics.checkNotNullParameter(event, "event");
            if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                return;
            }
            try {
                String eventName = event.a.getString("_eventName");
                if (Intrinsics.b(eventName, "_removed_")) {
                    return;
                }
                Intrinsics.checkNotNullExpressionValue(eventName, "eventName");
                if (!StringsKt.G(eventName, "gps", false) && a()) {
                    Context contextA = o.a();
                    try {
                        MeasurementManager measurementManagerK = i.k(contextA.getSystemService(i.t()));
                        if (measurementManagerK == null) {
                            measurementManagerK = MeasurementManager.get(contextA.getApplicationContext());
                        }
                        if (measurementManagerK == null) {
                            Log.w(str, "FAILURE_GET_MEASUREMENT_MANAGER");
                            com.facebook.appevents.gps.a aVar = d;
                            if (aVar == null) {
                                Intrinsics.m("gpsDebugLogger");
                                throw null;
                            }
                            Bundle bundle = new Bundle();
                            bundle.putString("gps_ara_failed_reason", "Failed to get measurement manager");
                            Unit unit = Unit.a;
                            aVar.a(bundle, "gps_ara_failed");
                            return;
                        }
                        String strB = b(event);
                        StringBuilder sb = new StringBuilder();
                        String str2 = e;
                        if (str2 == null) {
                            Intrinsics.m("serverUri");
                            throw null;
                        }
                        sb.append(str2);
                        sb.append("?app_id=");
                        sb.append(applicationId);
                        sb.append('&');
                        sb.append(strB);
                        Uri uri = Uri.parse(sb.toString());
                        Intrinsics.checkNotNullExpressionValue(uri, "parse(\"$serverUri?$appId…=$applicationId&$params\")");
                        measurementManagerK.registerTrigger(uri, o.c(), new b(0));
                    } catch (Error e2) {
                        Log.w(str, "FAILURE_TRIGGER_REGISTRATION_FAILED");
                        com.facebook.appevents.gps.a aVar2 = d;
                        if (aVar2 == null) {
                            Intrinsics.m("gpsDebugLogger");
                            throw null;
                        }
                        Bundle bundle2 = new Bundle();
                        bundle2.putString("gps_ara_failed_reason", e2.toString());
                        Unit unit2 = Unit.a;
                        aVar2.a(bundle2, "gps_ara_failed");
                    } catch (Exception e3) {
                        Log.w(str, "FAILURE_TRIGGER_REGISTRATION_FAILED");
                        com.facebook.appevents.gps.a aVar3 = d;
                        if (aVar3 == null) {
                            Intrinsics.m("gpsDebugLogger");
                            throw null;
                        }
                        Bundle bundle3 = new Bundle();
                        bundle3.putString("gps_ara_failed_reason", e3.toString());
                        Unit unit3 = Unit.a;
                        aVar3.a(bundle3, "gps_ara_failed");
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }
}
