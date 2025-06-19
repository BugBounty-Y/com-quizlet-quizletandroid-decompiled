package com.google.android.gms.internal.ads;

import android.app.ActivityManager;
import android.app.Application;
import android.app.UiModeManager;
import android.content.Context;
import android.content.IntentFilter;
import android.os.Handler;
import android.os.RemoteException;
import android.view.View;
import android.view.WindowManager;
import android.webkit.WebView;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.tasks.Task;
import java.lang.ref.WeakReference;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.Executor;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.hi, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2147hi implements Xh, Pv, Gq, InterfaceC2139ha, InterfaceC2183ia, InterfaceC2316lg, com.google.android.gms.tasks.a {
    public final /* synthetic */ int a;

    public C2147hi(int i) {
        this.a = 29;
    }

    public static C2665tm a(int i, int i2, WebView webView, String str, String str2, String str3) {
        Object objL = null;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() || !AbstractC1972di.M.b) {
            return null;
        }
        try {
            objL = new androidx.compose.foundation.lazy.grid.m(i2, i, webView, str, str2, str3).l();
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.j.C.h.g("omid exception", e);
        }
        return (C2665tm) objL;
    }

    private final void d(Throwable th) {
    }

    public static com.quizlet.data.repository.studysetwithcreatorinclass.g e(VersionInfoParcel versionInfoParcel, WebView webView) {
        try {
            return new com.quizlet.data.repository.studysetwithcreatorinclass.g(A7.a("Google", versionInfoParcel.b + "." + versionInfoParcel.c), webView);
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.j.C.h.g("omid exception", e);
            return null;
        }
    }

    public static String g() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue()) {
            return "a.1.5.2-google_20241009";
        }
        return null;
    }

    public static final Set i(Qk qk, Executor executor) {
        return ((Boolean) Y7.a.o()).booleanValue() ? Collections.singleton(new C2318li(qk, executor)) : Collections.EMPTY_SET;
    }

    public static void j(Hr hr, View view) {
        p(new RunnableC2451om(hr, view, 1));
    }

    public static void k(Hr hr) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() && AbstractC1972di.M.b) {
            p(new RunnableC2494pm(hr, 0));
        }
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [com.google.android.gms.internal.ads.rm] */
    public static boolean l(final Context context) {
        Object objA;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue()) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid flag is disabled");
            return false;
        }
        try {
            objA = new Object() { // from class: com.google.android.gms.internal.ads.rm
                public final Object a() {
                    int i = 1;
                    androidx.camera.camera2.internal.compat.workaround.e eVar = AbstractC1972di.M;
                    if (eVar.b) {
                        return Boolean.TRUE;
                    }
                    Context applicationContext = context.getApplicationContext();
                    if (applicationContext == null) {
                        throw new IllegalArgumentException("Application Context cannot be null");
                    }
                    if (!eVar.b) {
                        eVar.b = true;
                        Xr xrB = Xr.b();
                        xrB.getClass();
                        xrB.b = new Nr(new Handler(), applicationContext, xrB);
                        Pr pr = Pr.e;
                        boolean z = applicationContext instanceof Application;
                        if (z) {
                            ((Application) applicationContext).registerActivityLifecycleCallbacks(pr);
                        }
                        AbstractC1972di.N = (UiModeManager) applicationContext.getSystemService("uimode");
                        WindowManager windowManager = AbstractC1938cs.a;
                        AbstractC1938cs.c = applicationContext.getResources().getDisplayMetrics().density;
                        AbstractC1938cs.a = (WindowManager) applicationContext.getSystemService("window");
                        applicationContext.registerReceiver(new com.google.android.gms.ads.internal.util.E(2), new IntentFilter("android.media.action.HDMI_AUDIO_PLUG"));
                        Wr.b.a = applicationContext.getApplicationContext();
                        Or or = Or.e;
                        if (!or.a) {
                            Sr sr = (Sr) or.d;
                            if (z) {
                                ((Application) applicationContext).registerActivityLifecycleCallbacks(sr);
                            }
                            sr.d = or;
                            sr.b = true;
                            ActivityManager.RunningAppProcessInfo runningAppProcessInfo = new ActivityManager.RunningAppProcessInfo();
                            ActivityManager.getMyMemoryState(runningAppProcessInfo);
                            sr.c = runningAppProcessInfo.importance == 100;
                            or.b = sr.c;
                            or.a = true;
                        }
                        Yr.d.a = new WeakReference(applicationContext);
                        IntentFilter intentFilter = new IntentFilter("android.intent.action.SCREEN_OFF");
                        intentFilter.addAction("android.intent.action.SCREEN_ON");
                        applicationContext.registerReceiver(new com.google.android.gms.ads.internal.util.E(i), intentFilter);
                    }
                    return Boolean.valueOf(eVar.b);
                }
            }.a();
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.j.C.h.g("omid exception", e);
            objA = null;
        }
        Boolean bool = (Boolean) objA;
        return bool != null && bool.booleanValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.Ir m(java.lang.String r4) {
        /*
            int r0 = r4.hashCode()
            r1 = -382745961(0xffffffffe92fc297, float:-1.3280059E25)
            r2 = 2
            r3 = 1
            if (r0 == r1) goto L2a
            r1 = 112202875(0x6b0147b, float:6.6233935E-35)
            if (r0 == r1) goto L20
            r1 = 714893483(0x2a9c68ab, float:2.7783795E-13)
            if (r0 == r1) goto L16
            goto L34
        L16:
            java.lang.String r0 = "nativeDisplay"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = r3
            goto L35
        L20:
            java.lang.String r0 = "video"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = r2
            goto L35
        L2a:
            java.lang.String r0 = "htmlDisplay"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = 0
            goto L35
        L34:
            r4 = -1
        L35:
            if (r4 == 0) goto L43
            if (r4 == r3) goto L40
            if (r4 == r2) goto L3d
            r4 = 0
            return r4
        L3d:
            com.google.android.gms.internal.ads.Ir r4 = com.google.android.gms.internal.ads.Ir.VIDEO
            return r4
        L40:
            com.google.android.gms.internal.ads.Ir r4 = com.google.android.gms.internal.ads.Ir.NATIVE_DISPLAY
            return r4
        L43:
            com.google.android.gms.internal.ads.Ir r4 = com.google.android.gms.internal.ads.Ir.HTML_DISPLAY
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2147hi.m(java.lang.String):com.google.android.gms.internal.ads.Ir");
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0034  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.Kr n(java.lang.String r4) {
        /*
            int r0 = r4.hashCode()
            r1 = -1104128070(0xffffffffbe3057ba, float:-0.17220965)
            r2 = 1
            r3 = 2
            if (r0 == r1) goto L2a
            r1 = 1318088141(0x4e906dcd, float:1.2115575E9)
            if (r0 == r1) goto L20
            r1 = 1988248512(0x768243c0, float:1.3210405E33)
            if (r0 == r1) goto L16
            goto L34
        L16:
            java.lang.String r0 = "onePixel"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = r3
            goto L35
        L20:
            java.lang.String r0 = "definedByJavascript"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = r2
            goto L35
        L2a:
            java.lang.String r0 = "beginToRender"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L34
            r4 = 0
            goto L35
        L34:
            r4 = -1
        L35:
            if (r4 == 0) goto L44
            if (r4 == r2) goto L41
            if (r4 == r3) goto L3e
            com.google.android.gms.internal.ads.Kr r4 = com.google.android.gms.internal.ads.Kr.UNSPECIFIED
            return r4
        L3e:
            com.google.android.gms.internal.ads.Kr r4 = com.google.android.gms.internal.ads.Kr.ONE_PIXEL
            return r4
        L41:
            com.google.android.gms.internal.ads.Kr r4 = com.google.android.gms.internal.ads.Kr.DEFINED_BY_JAVASCRIPT
            return r4
        L44:
            com.google.android.gms.internal.ads.Kr r4 = com.google.android.gms.internal.ads.Kr.BEGIN_TO_RENDER
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2147hi.n(java.lang.String):com.google.android.gms.internal.ads.Kr");
    }

    public static Mr o(String str) {
        return com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE.equals(str) ? Mr.NATIVE : "javascript".equals(str) ? Mr.JAVASCRIPT : Mr.NONE;
    }

    public static final void p(Runnable runnable) {
        try {
            runnable.run();
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.j.C.h.g("omid exception", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        com.google.android.gms.ads.internal.client.w0 w0VarZzi;
        com.google.android.gms.ads.internal.client.w0 w0VarZzi2;
        com.google.android.gms.ads.internal.client.w0 w0VarZzi3;
        switch (this.a) {
            case 0:
                ((InterfaceC2103gi) obj).b();
                break;
            case 1:
                ((InterfaceC2275ki) obj).d();
                break;
            case 2:
                ((InterfaceC2447oi) obj).c();
                break;
            case 3:
                ((InterfaceC2447oi) obj).c0();
                break;
            case 4:
                C2533qi c2533qi = (C2533qi) obj;
                if (!c2533qi.d) {
                    c2533qi.b.b(c2533qi.a, c2533qi.c);
                    c2533qi.d = true;
                    break;
                }
                break;
            case 5:
                ((InterfaceC2818x9) obj).q();
                break;
            case 6:
                ((InterfaceC2818x9) obj).b();
                break;
            case 7:
                com.google.android.gms.ads.internal.client.v0 v0VarI = ((C2017ek) obj).a.i();
                if (v0VarI == null) {
                    w0VarZzi = null;
                } else {
                    try {
                        w0VarZzi = v0VarI.zzi();
                    } catch (RemoteException unused) {
                    }
                }
                if (w0VarZzi != null) {
                    try {
                        w0VarZzi.h();
                        break;
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("Unable to call onVideoEnd()", e);
                        return;
                    }
                }
                break;
            case 8:
                com.google.android.gms.ads.internal.client.v0 v0VarI2 = ((C2017ek) obj).a.i();
                if (v0VarI2 == null) {
                    w0VarZzi2 = null;
                } else {
                    try {
                        w0VarZzi2 = v0VarI2.zzi();
                    } catch (RemoteException unused2) {
                    }
                }
                if (w0VarZzi2 != null) {
                    try {
                        w0VarZzi2.zze();
                        break;
                    } catch (RemoteException e2) {
                        com.google.android.gms.ads.internal.util.client.i.i("Unable to call onVideoEnd()", e2);
                        return;
                    }
                }
                break;
            case 9:
                com.google.android.gms.ads.internal.client.v0 v0VarI3 = ((C2017ek) obj).a.i();
                if (v0VarI3 == null) {
                    w0VarZzi3 = null;
                } else {
                    try {
                        w0VarZzi3 = v0VarI3.zzi();
                    } catch (RemoteException unused3) {
                    }
                }
                if (w0VarZzi3 != null) {
                    try {
                        w0VarZzi3.zzi();
                        break;
                    } catch (RemoteException e3) {
                        com.google.android.gms.ads.internal.util.client.i.i("Unable to call onVideoEnd()", e3);
                        return;
                    }
                }
                break;
            case 10:
                ((C2017ek) obj).getClass();
                break;
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case EventType.SUBS /* 25 */:
            default:
                ((InterfaceC2569rc) obj).zze();
                break;
            case 21:
                ((InterfaceC1622x) obj).h();
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((com.google.android.gms.ads.internal.overlay.j) obj).f3();
                break;
            case EventType.AUDIO /* 23 */:
                ((InterfaceC2832xh) obj).h();
                break;
            case EventType.VIDEO /* 24 */:
                ((com.google.android.gms.ads.internal.overlay.j) obj).L2();
                break;
            case EventType.CDN /* 26 */:
                ((com.google.android.gms.ads.rewarded.a) obj).j();
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2183ia
    public JSONObject c(Object obj) throws JSONException {
        Sl sl = (Sl) obj;
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        JSONObject jSONObject3 = new JSONObject();
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.n9)).booleanValue()) {
            C1810Zb c1810Zb = sl.c;
            jSONObject2.put("ad_request_url", c1810Zb.f);
            jSONObject2.put("ad_request_post_body", c1810Zb.c);
        }
        C1810Zb c1810Zb2 = sl.c;
        jSONObject2.put("base_url", c1810Zb2.b);
        jSONObject2.put("signals", sl.b);
        Vl vl = sl.a;
        jSONObject3.put("body", vl.c);
        jSONObject3.put("headers", C1614q.f.a.i(vl.b));
        jSONObject3.put("response_code", vl.a);
        jSONObject3.put("latency", vl.d);
        jSONObject.put("request", jSONObject2);
        jSONObject.put("response", jSONObject3);
        jSONObject.put("flags", c1810Zb2.h);
        return jSONObject;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2139ha
    public Object f(JSONObject jSONObject) {
        return new C1810Zb(jSONObject);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        return Boolean.valueOf(task.l());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2316lg
    public com.google.android.gms.ads.internal.client.v0 zza() {
        return null;
    }

    public /* synthetic */ C2147hi(int i, byte b) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 11:
                break;
            default:
                com.google.android.gms.ads.internal.util.A.l("Notification of cache hit failed.");
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public /* synthetic */ void mo15c(Object obj) {
        switch (this.a) {
            case 11:
                ((InterfaceC2529qe) obj).destroy();
                break;
            default:
                com.google.android.gms.ads.internal.util.A.l("Notification of cache hit successful.");
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        JSONObject jSONObject = (JSONObject) obj;
        com.google.android.gms.ads.internal.util.A.l("Ad request signals:");
        com.google.android.gms.ads.internal.util.A.l(jSONObject.toString(2));
        return jSONObject;
    }
}
