package com.facebook.appevents.codeless;

import android.app.Activity;
import android.util.Log;
import android.view.View;
import com.facebook.o;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.quizlet.quizletandroid.C;
import java.lang.ref.WeakReference;
import java.util.TimerTask;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import kotlin.coroutines.n;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class j extends TimerTask {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ j(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.h] */
    /* JADX WARN: Type inference failed for: r1v15 */
    /* JADX WARN: Type inference failed for: r1v16 */
    /* JADX WARN: Type inference failed for: r1v4, types: [android.os.Handler] */
    @Override // java.util.TimerTask, java.lang.Runnable
    public final void run() throws Throwable {
        WeakReference weakReference;
        boolean z = false;
        z = false;
        ?? r1 = 0;
        r1 = 0;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                try {
                    k kVar = (k) obj;
                    if (com.facebook.internal.instrument.crashshield.a.b(k.class)) {
                        weakReference = null;
                    } else {
                        try {
                            weakReference = kVar.b;
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(k.class, th);
                        }
                    }
                    Activity activity = (Activity) weakReference.get();
                    View viewC = com.facebook.appevents.internal.d.c(activity);
                    if (activity != null && viewC != null) {
                        String simpleName = activity.getClass().getSimpleName();
                        d dVar = d.a;
                        if (!com.facebook.internal.instrument.crashshield.a.b(d.class)) {
                            try {
                                z = d.g.get();
                            } catch (Throwable th2) {
                                com.facebook.internal.instrument.crashshield.a.a(d.class, th2);
                            }
                        }
                        if (!z) {
                            break;
                        } else {
                            FutureTask futureTask = new FutureTask(new androidx.camera.core.impl.utils.executor.c(viewC));
                            if (!com.facebook.internal.instrument.crashshield.a.b(k.class)) {
                                try {
                                    r1 = kVar.a;
                                } catch (Throwable th3) {
                                    com.facebook.internal.instrument.crashshield.a.a(k.class, th3);
                                }
                            }
                            r1.post(futureTask);
                            String str = "";
                            try {
                                str = (String) futureTask.get(1L, TimeUnit.SECONDS);
                            } catch (Exception e) {
                                Log.e(k.a(), "Failed to take screenshot.", e);
                            }
                            JSONObject jSONObject = new JSONObject();
                            try {
                                jSONObject.put("screenname", simpleName);
                                jSONObject.put("screenshot", str);
                                JSONArray jSONArray = new JSONArray();
                                jSONArray.put(com.facebook.appevents.codeless.internal.g.c(viewC));
                                jSONObject.put("view", jSONArray);
                            } catch (JSONException unused) {
                                Log.e(k.a(), "Failed to create JSONObject");
                            }
                            String string = jSONObject.toString();
                            Intrinsics.checkNotNullExpressionValue(string, "viewTree.toString()");
                            if (!com.facebook.internal.instrument.crashshield.a.b(k.class)) {
                                try {
                                    kVar.getClass();
                                    if (!com.facebook.internal.instrument.crashshield.a.b(kVar)) {
                                        try {
                                            o.c().execute(new androidx.credentials.playservices.controllers.c(22, string, kVar));
                                            break;
                                        } catch (Throwable th4) {
                                            com.facebook.internal.instrument.crashshield.a.a(kVar, th4);
                                            return;
                                        }
                                    }
                                } catch (Throwable th5) {
                                    com.facebook.internal.instrument.crashshield.a.a(k.class, th5);
                                    return;
                                }
                            }
                        }
                    }
                } catch (Exception e2) {
                    Log.e(k.a(), "UI Component tree indexing failure!", e2);
                    return;
                }
                break;
            case 1:
                E.D(n.a, new com.perimeterx.mobile_sdk.session.a((com.perimeterx.mobile_sdk.session.d) obj, r1, z ? 1 : 0));
                break;
            default:
                C c = (C) obj;
                c.c.post(new q(c, 13));
                break;
        }
    }
}
