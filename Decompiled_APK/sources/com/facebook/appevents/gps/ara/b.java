package com.facebook.appevents.gps.ara;

import android.os.Bundle;
import android.os.OutcomeReceiver;
import android.util.Log;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements OutcomeReceiver {
    public final /* synthetic */ int a;

    public final void onError(Throwable th) {
        com.facebook.appevents.gps.a aVar;
        String str;
        com.facebook.appevents.gps.a aVar2;
        switch (this.a) {
            case 0:
                Exception error = (Exception) th;
                Intrinsics.checkNotNullParameter(error, "error");
                com.facebook.internal.instrument.crashshield.a.b(c.class);
                if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
                    aVar = null;
                } else {
                    try {
                        aVar = c.d;
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(c.class, th2);
                    }
                }
                if (aVar == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle = new Bundle();
                bundle.putString("gps_ara_failed_reason", error.toString());
                Unit unit = Unit.a;
                aVar.a(bundle, "gps_ara_failed");
                return;
            default:
                Exception error2 = (Exception) th;
                Intrinsics.checkNotNullParameter(error2, "error");
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.pa.b.class)) {
                    str = null;
                } else {
                    try {
                        str = com.facebook.appevents.gps.pa.b.b;
                    } catch (Throwable th3) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.pa.b.class, th3);
                    }
                }
                Log.e(str, error2.toString());
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.pa.b.class)) {
                    aVar2 = null;
                } else {
                    try {
                        aVar2 = com.facebook.appevents.gps.pa.b.f;
                    } catch (Throwable th4) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.pa.b.class, th4);
                    }
                }
                if (aVar2 == null) {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
                Bundle bundle2 = new Bundle();
                bundle2.putString("gps_pa_failed_reason", error2.toString());
                Unit unit2 = Unit.a;
                aVar2.a(bundle2, "gps_pa_failed");
                return;
        }
    }

    public final void onResult(Object result) {
        com.facebook.appevents.gps.a aVar;
        String str;
        com.facebook.appevents.gps.a aVar2;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(result, "result");
                com.facebook.internal.instrument.crashshield.a.b(c.class);
                if (com.facebook.internal.instrument.crashshield.a.b(c.class)) {
                    aVar = null;
                } else {
                    try {
                        aVar = c.d;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(c.class, th);
                    }
                }
                if (aVar != null) {
                    aVar.a(null, "gps_ara_succeed");
                    return;
                } else {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
            default:
                Intrinsics.checkNotNullParameter(result, "result");
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.pa.b.class)) {
                    str = null;
                } else {
                    try {
                        str = com.facebook.appevents.gps.pa.b.b;
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.pa.b.class, th2);
                    }
                }
                Log.i(str, "Successfully joined custom audience");
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.gps.pa.b.class)) {
                    aVar2 = null;
                } else {
                    try {
                        aVar2 = com.facebook.appevents.gps.pa.b.f;
                    } catch (Throwable th3) {
                        com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.gps.pa.b.class, th3);
                    }
                }
                if (aVar2 != null) {
                    aVar2.a(null, "gps_pa_succeed");
                    return;
                } else {
                    Intrinsics.m("gpsDebugLogger");
                    throw null;
                }
        }
    }
}
