package com.facebook.appevents.ondeviceprocessing;

import android.os.Bundle;
import com.facebook.internal.v;
import com.facebook.internal.y;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();

    public static final Bundle a(c eventType, String applicationId, List appEvents) {
        if (!com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            try {
                Intrinsics.checkNotNullParameter(eventType, "eventType");
                Intrinsics.checkNotNullParameter(applicationId, "applicationId");
                Intrinsics.checkNotNullParameter(appEvents, "appEvents");
                Bundle bundle = new Bundle();
                bundle.putString("event", eventType.a);
                bundle.putString("app_id", applicationId);
                if (c.CUSTOM_APP_EVENTS != eventType) {
                    return bundle;
                }
                JSONArray jSONArrayB = a.b(applicationId, appEvents);
                if (jSONArrayB.length() != 0) {
                    bundle.putString("custom_events", jSONArrayB.toString());
                    return bundle;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(b.class, th);
                return null;
            }
        }
        return null;
    }

    public final JSONArray b(String str, List list) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            JSONArray jSONArray = new JSONArray();
            ArrayList arrayListY0 = CollectionsKt.y0(list);
            com.facebook.appevents.eventdeactivation.b.b(arrayListY0);
            boolean z = false;
            if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                try {
                    v vVarK = y.k(str, false);
                    if (vVarK != null) {
                        z = vVarK.a;
                    }
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                }
            }
            Iterator it2 = arrayListY0.iterator();
            while (it2.hasNext()) {
                com.facebook.appevents.e eVar = (com.facebook.appevents.e) it2.next();
                boolean z2 = eVar.c;
                if (!z2 || (z2 && z)) {
                    jSONArray.put(eVar.a);
                }
            }
            return jSONArray;
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
            return null;
        }
    }
}
