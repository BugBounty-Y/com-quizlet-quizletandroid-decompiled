package com.facebook.appevents;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.compose.ui.text.input.C;
import com.facebook.C1545b;
import com.facebook.FacebookRequestError;
import com.facebook.internal.A;
import com.facebook.internal.J;
import com.facebook.internal.y;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class h {
    public static ScheduledFuture c;
    public static volatile com.bumptech.glide.f a = new com.bumptech.glide.f(1);
    public static final ScheduledExecutorService b = Executors.newSingleThreadScheduledExecutor();
    public static final RunnableC0131h d = new RunnableC0131h(5);

    public static final com.facebook.t a(b accessTokenAppId, u appEvents, boolean z, com.android.billingclient.api.s flushState) {
        if (!com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            try {
                Intrinsics.checkNotNullParameter(accessTokenAppId, "accessTokenAppId");
                Intrinsics.checkNotNullParameter(appEvents, "appEvents");
                Intrinsics.checkNotNullParameter(flushState, "flushState");
                String str = accessTokenAppId.a;
                com.facebook.internal.v vVarK = y.k(str, false);
                String str2 = com.facebook.t.j;
                String str3 = String.format("%s/activities", Arrays.copyOf(new Object[]{str}, 1));
                Intrinsics.checkNotNullExpressionValue(str3, "format(format, *args)");
                com.facebook.t tVarR = assistantMode.utils.studiableMetadata.b.R(null, str3, null, null);
                tVarR.i = true;
                Bundle bundle = tVarR.d;
                if (bundle == null) {
                    bundle = new Bundle();
                }
                bundle.putString("access_token", accessTokenAppId.b);
                synchronized (j.c()) {
                    com.facebook.internal.instrument.crashshield.a.b(j.class);
                }
                String str4 = j.c;
                String strI = com.google.firebase.perf.logging.b.i();
                if (strI != null) {
                    bundle.putString("install_referrer", strI);
                }
                Intrinsics.checkNotNullParameter(bundle, "<set-?>");
                tVarR.d = bundle;
                int iC = appEvents.c(tVarR, com.facebook.o.a(), vVarK != null ? vVarK.a : false, z);
                if (iC != 0) {
                    flushState.b += iC;
                    tVarR.j(new C1545b(accessTokenAppId, tVarR, appEvents, flushState, 1));
                    return tVarR;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(h.class, th);
                return null;
            }
        }
        return null;
    }

    public static final ArrayList b(com.bumptech.glide.f appEventCollection, com.android.billingclient.api.s flushResults) {
        if (com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(appEventCollection, "appEventCollection");
            Intrinsics.checkNotNullParameter(flushResults, "flushResults");
            boolean zF = com.facebook.o.f(com.facebook.o.a());
            ArrayList arrayList = new ArrayList();
            for (b bVar : appEventCollection.e()) {
                u uVarB = appEventCollection.b(bVar);
                if (uVarB == null) {
                    throw new IllegalStateException("Required value was null.");
                }
                com.facebook.t request = a(bVar, uVarB, zF, flushResults);
                if (request != null) {
                    arrayList.add(request);
                    if (com.facebook.appevents.cloudbridge.c.a) {
                        HashSet hashSet = com.facebook.appevents.cloudbridge.h.a;
                        Intrinsics.checkNotNullParameter(request, "request");
                        J.M(new C(request, 17));
                    }
                }
            }
            return arrayList;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(h.class, th);
            return null;
        }
    }

    public static final void c(n reason) {
        if (com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(reason, "reason");
            b.execute(new C(reason, 16));
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(h.class, th);
        }
    }

    public static final void d(n reason) {
        if (com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(reason, "reason");
            a.a(g.h());
            try {
                com.android.billingclient.api.s sVarF = f(reason, a);
                if (sVarF != null) {
                    Intent intent = new Intent("com.facebook.sdk.APP_EVENTS_FLUSHED");
                    intent.putExtra("com.facebook.sdk.APP_EVENTS_NUM_EVENTS_FLUSHED", sVarF.b);
                    intent.putExtra("com.facebook.sdk.APP_EVENTS_FLUSH_RESULT", (o) sVarF.c);
                    androidx.localbroadcastmanager.content.b.a(com.facebook.o.a()).c(intent);
                }
            } catch (Exception e) {
                Log.w("com.facebook.appevents.h", "Caught unexpected exception while flushing app events: ", e);
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(h.class, th);
        }
    }

    public static final void e(b accessTokenAppId, com.facebook.t request, com.facebook.w response, u appEvents, com.android.billingclient.api.s flushState) {
        o oVar;
        if (com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(accessTokenAppId, "accessTokenAppId");
            Intrinsics.checkNotNullParameter(request, "request");
            Intrinsics.checkNotNullParameter(response, "response");
            Intrinsics.checkNotNullParameter(appEvents, "appEvents");
            Intrinsics.checkNotNullParameter(flushState, "flushState");
            FacebookRequestError facebookRequestError = response.c;
            o oVar2 = o.a;
            o oVar3 = o.c;
            if (facebookRequestError == null) {
                oVar = oVar2;
            } else if (facebookRequestError.b == -1) {
                oVar = oVar3;
            } else {
                Intrinsics.checkNotNullExpressionValue(String.format("Failed:\n  Response: %s\n  Error %s", Arrays.copyOf(new Object[]{response.toString(), facebookRequestError.toString()}, 2)), "format(format, *args)");
                oVar = o.b;
            }
            com.facebook.o.h(com.facebook.y.d);
            boolean z = facebookRequestError != null;
            synchronized (appEvents) {
                if (!com.facebook.internal.instrument.crashshield.a.b(appEvents)) {
                    if (z) {
                        try {
                            appEvents.c.addAll(appEvents.d);
                            appEvents.d.clear();
                            appEvents.e = 0;
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(appEvents, th);
                        }
                    } else {
                        appEvents.d.clear();
                        appEvents.e = 0;
                    }
                }
            }
            if (oVar == oVar3) {
                com.facebook.o.c().execute(new androidx.credentials.playservices.controllers.c(16, accessTokenAppId, appEvents));
            }
            if (oVar == oVar2 || ((o) flushState.c) == oVar3) {
                return;
            }
            Intrinsics.checkNotNullParameter(oVar, "<set-?>");
            flushState.c = oVar;
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(h.class, th2);
        }
    }

    public static final com.android.billingclient.api.s f(n reason, com.bumptech.glide.f appEventCollection) {
        if (!com.facebook.internal.instrument.crashshield.a.b(h.class)) {
            try {
                Intrinsics.checkNotNullParameter(reason, "reason");
                Intrinsics.checkNotNullParameter(appEventCollection, "appEventCollection");
                com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(11, (char) 0);
                sVar.c = o.a;
                ArrayList arrayListB = b(appEventCollection, sVar);
                if (!arrayListB.isEmpty()) {
                    com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                    com.facebook.y yVar = com.facebook.y.d;
                    Intrinsics.checkNotNullExpressionValue("com.facebook.appevents.h", "TAG");
                    com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.h", "Flushing %d events due to %s.", Integer.valueOf(sVar.b), reason.toString());
                    Iterator it2 = arrayListB.iterator();
                    while (it2.hasNext()) {
                        ((com.facebook.t) it2.next()).c();
                    }
                    return sVar;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(h.class, th);
                return null;
            }
        }
        return null;
    }
}
