package com.facebook.appevents;

import android.content.Context;
import android.os.Bundle;
import com.facebook.internal.C1548c;
import com.facebook.internal.C1563s;
import com.facebook.internal.EnumC1562q;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class u {
    public final C1548c a;
    public final String b;
    public ArrayList c;
    public final ArrayList d;
    public int e;

    public u(C1548c attributionIdentifiers, String anonymousAppDeviceGUID) {
        Intrinsics.checkNotNullParameter(attributionIdentifiers, "attributionIdentifiers");
        Intrinsics.checkNotNullParameter(anonymousAppDeviceGUID, "anonymousAppDeviceGUID");
        this.a = attributionIdentifiers;
        this.b = anonymousAppDeviceGUID;
        this.c = new ArrayList();
        this.d = new ArrayList();
    }

    public final synchronized void a(e event) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(event, "event");
            if (this.c.size() + this.d.size() >= 1000) {
                this.e++;
            } else {
                this.c.add(event);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final synchronized List b() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            ArrayList arrayList = this.c;
            this.c = new ArrayList();
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final int c(com.facebook.t request, Context applicationContext, boolean z, boolean z2) {
        Throwable th;
        Throwable th2;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return 0;
        }
        try {
            Intrinsics.checkNotNullParameter(request, "request");
            Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
            try {
                synchronized (this) {
                    try {
                        int i = this.e;
                        com.facebook.appevents.eventdeactivation.b.b(this.c);
                        this.d.addAll(this.c);
                        this.c.clear();
                        JSONArray jSONArray = new JSONArray();
                        JSONArray jSONArray2 = new JSONArray();
                        Iterator it2 = this.d.iterator();
                        while (it2.hasNext()) {
                            try {
                                e eVar = (e) it2.next();
                                if (z || !eVar.c) {
                                    jSONArray.put(eVar.a);
                                    jSONArray2.put(eVar.b);
                                }
                            } catch (Throwable th3) {
                                th2 = th3;
                                throw th2;
                            }
                        }
                        if (jSONArray.length() != 0) {
                            Unit unit = Unit.a;
                            d(request, applicationContext, i, jSONArray, jSONArray2, z2);
                            return jSONArray.length();
                        }
                        try {
                            return 0;
                        } catch (Throwable th4) {
                            th = th4;
                            com.facebook.internal.instrument.crashshield.a.a(this, th);
                            return 0;
                        }
                    } catch (Throwable th5) {
                        th2 = th5;
                    }
                }
            } catch (Throwable th6) {
                th = th6;
                th = th;
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return 0;
            }
        } catch (Throwable th7) {
            th = th7;
        }
    }

    public final void d(com.facebook.t tVar, Context context, int i, JSONArray jSONArray, JSONArray jSONArray2, boolean z) {
        JSONObject jSONObject;
        try {
            if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                return;
            }
            try {
                jSONObject = com.facebook.appevents.internal.f.a(com.facebook.appevents.internal.e.b, this.a, this.b, z, context);
                if (this.e > 0) {
                    jSONObject.put("num_skipped_events", i);
                }
            } catch (JSONException unused) {
                jSONObject = new JSONObject();
            }
            tVar.c = jSONObject;
            Bundle bundle = tVar.d;
            String string = jSONArray.toString();
            Intrinsics.checkNotNullExpressionValue(string, "events.toString()");
            bundle.putString("custom_events", string);
            if (C1563s.b(EnumC1562q.IapLoggingLib5To7)) {
                bundle.putString("operational_parameters", jSONArray2.toString());
            }
            tVar.e = string;
            Intrinsics.checkNotNullParameter(bundle, "<set-?>");
            tVar.d = bundle;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
