package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Color;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.ViewGroup;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.ads.internal.client.C1614q;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Md, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1734Md implements InterfaceC2389n9 {
    public boolean a;

    public static int a(Context context, Map map, String str, int i) {
        String str2 = (String) map.get(str);
        if (str2 != null) {
            try {
                com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                i = com.google.android.gms.ads.internal.util.client.c.n(context, Integer.parseInt(str2));
            } catch (NumberFormatException unused) {
                com.google.android.gms.ads.internal.util.client.i.h("Could not parse " + str + " in a video GMSG: " + str2);
            }
        }
        if (com.google.android.gms.ads.internal.util.A.m()) {
            StringBuilder sbH = AbstractC0147y.h("Parse pixels for ", str, ", got string ", str2, ", int ");
            sbH.append(i);
            sbH.append(".");
            com.google.android.gms.ads.internal.util.A.l(sbH.toString());
        }
        return i;
    }

    public static void b(C2785wd c2785wd, Map map) throws NumberFormatException {
        String str = (String) map.get("minBufferMs");
        String str2 = (String) map.get("maxBufferMs");
        String str3 = (String) map.get("bufferForPlaybackMs");
        String str4 = (String) map.get("bufferForPlaybackAfterRebufferMs");
        String str5 = (String) map.get("socketReceiveBufferSize");
        AbstractC2656td abstractC2656td = c2785wd.g;
        if (str != null) {
            try {
                int i = Integer.parseInt(str);
                if (abstractC2656td != null) {
                    abstractC2656td.b(i);
                }
            } catch (NumberFormatException unused) {
                com.google.android.gms.ads.internal.util.client.i.h("Could not parse buffer parameters in loadControl video GMSG: (" + str + ", " + str2 + ")");
                return;
            }
        }
        if (str2 != null) {
            int i2 = Integer.parseInt(str2);
            if (abstractC2656td != null) {
                abstractC2656td.D(i2);
            }
        }
        if (str3 != null) {
            int i3 = Integer.parseInt(str3);
            if (abstractC2656td != null) {
                abstractC2656td.B(i3);
            }
        }
        if (str4 != null) {
            int i4 = Integer.parseInt(str4);
            if (abstractC2656td != null) {
                abstractC2656td.C(i4);
            }
        }
        if (str5 != null) {
            int i5 = Integer.parseInt(str5);
            if (abstractC2656td == null) {
                return;
            }
            abstractC2656td.c(i5);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) throws JSONException, NumberFormatException {
        int iMin;
        int iMin2;
        int i;
        boolean z;
        int i2;
        C2785wd c2785wd;
        AbstractC2656td abstractC2656td;
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) obj;
        String str = (String) map.get("action");
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Action missing from video GMSG.");
            return;
        }
        Integer numValueOf = map.containsKey("playerId") ? Integer.valueOf(Integer.parseInt((String) map.get("playerId"))) : null;
        Integer numA = (interfaceC2529qe.m() == null || (c2785wd = (C2785wd) interfaceC2529qe.m().f) == null || (abstractC2656td = c2785wd.g) == null) ? null : abstractC2656td.A();
        if (numValueOf != null && numA != null && !numValueOf.equals(numA) && !str.equals("load")) {
            Locale locale = Locale.US;
            com.google.android.gms.ads.internal.util.client.i.g("Event intended for player " + numValueOf + ", but sent to player " + numA + " - event ignored");
            return;
        }
        Integer numValueOf2 = null;
        if (com.google.android.gms.ads.internal.util.client.i.k(3)) {
            JSONObject jSONObject = new JSONObject(map);
            jSONObject.remove("google.afma.Notify_dt");
            com.google.android.gms.ads.internal.util.client.i.d("Video GMSG: " + str + " " + jSONObject.toString());
        }
        if (str.equals("background")) {
            String str2 = (String) map.get("color");
            if (TextUtils.isEmpty(str2)) {
                com.google.android.gms.ads.internal.util.client.i.h("Color parameter missing from background video GMSG.");
                return;
            }
            try {
                interfaceC2529qe.setBackgroundColor(Color.parseColor(str2));
                return;
            } catch (IllegalArgumentException unused) {
                com.google.android.gms.ads.internal.util.client.i.h("Invalid color parameter in background video GMSG.");
                return;
            }
        }
        if (str.equals("playerBackground")) {
            String str3 = (String) map.get("color");
            if (TextUtils.isEmpty(str3)) {
                com.google.android.gms.ads.internal.util.client.i.h("Color parameter missing from playerBackground video GMSG.");
                return;
            }
            try {
                interfaceC2529qe.t(Color.parseColor(str3));
                return;
            } catch (IllegalArgumentException unused2) {
                com.google.android.gms.ads.internal.util.client.i.h("Invalid color parameter in playerBackground video GMSG.");
                return;
            }
        }
        if (str.equals("decoderProps")) {
            String str4 = (String) map.get("mimeTypes");
            if (str4 == null) {
                com.google.android.gms.ads.internal.util.client.i.h("No MIME types specified for decoder properties inspection.");
                HashMap map2 = new HashMap();
                map2.put("event", "decoderProps");
                map2.put("error", "missingMimeTypes");
                interfaceC2529qe.j("onVideoEvent", map2);
                return;
            }
            HashMap map3 = new HashMap();
            for (String str5 : str4.split(",")) {
                map3.put(str5, com.google.android.gms.ads.internal.util.z.a(str5.trim()));
            }
            HashMap map4 = new HashMap();
            map4.put("event", "decoderProps");
            map4.put("mimeTypes", map3);
            interfaceC2529qe.j("onVideoEvent", map4);
            return;
        }
        com.quizlet.remote.model.notes.e eVarM = interfaceC2529qe.m();
        if (eVarM == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not get underlay container for a video GMSG.");
            return;
        }
        boolean zEquals = str.equals("new");
        boolean zEquals2 = str.equals("position");
        if (zEquals || zEquals2) {
            Context context = interfaceC2529qe.getContext();
            int iA = a(context, map, "x", 0);
            int iA2 = a(context, map, "y", 0);
            int iA3 = a(context, map, "w", -1);
            C2601s7 c2601s7 = AbstractC2773w7.X3;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                iMin = iA3 == -1 ? interfaceC2529qe.g() : Math.min(iA3, interfaceC2529qe.g());
            } else {
                if (com.google.android.gms.ads.internal.util.A.m()) {
                    StringBuilder sbW = android.support.v4.media.session.a.w("Calculate width with original width ", iA3, ", videoHost.getVideoBoundingWidth() ", ", x ", interfaceC2529qe.g());
                    sbW.append(iA);
                    sbW.append(".");
                    com.google.android.gms.ads.internal.util.A.l(sbW.toString());
                }
                iMin = Math.min(iA3, interfaceC2529qe.g() - iA);
            }
            int iA4 = a(context, map, "h", -1);
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                iMin2 = iA4 == -1 ? interfaceC2529qe.h() : Math.min(iA4, interfaceC2529qe.h());
            } else {
                if (com.google.android.gms.ads.internal.util.A.m()) {
                    StringBuilder sbW2 = android.support.v4.media.session.a.w("Calculate height with original height ", iA4, ", videoHost.getVideoBoundingHeight() ", ", y ", interfaceC2529qe.h());
                    sbW2.append(iA2);
                    sbW2.append(".");
                    com.google.android.gms.ads.internal.util.A.l(sbW2.toString());
                }
                iMin2 = Math.min(iA4, interfaceC2529qe.h() - iA2);
            }
            try {
                i = Integer.parseInt((String) map.get("player"));
            } catch (NumberFormatException unused3) {
                i = 0;
            }
            boolean z2 = Boolean.parseBoolean((String) map.get("spherical"));
            if (!zEquals || ((C2785wd) eVarM.f) != null) {
                com.google.android.gms.common.internal.u.d("The underlay may only be modified from the UI thread.");
                C2785wd c2785wd2 = (C2785wd) eVarM.f;
                if (c2785wd2 != null) {
                    c2785wd2.a(iA, iA2, iMin, iMin2);
                    return;
                }
                return;
            }
            C1668Bd c1668Bd = new C1668Bd((String) map.get("flags"));
            if (((C2785wd) eVarM.f) == null) {
                C2743ve c2743ve = (C2743ve) eVarM.c;
                ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
                AbstractC2096gb.h((B7) viewTreeObserverOnGlobalLayoutListenerC2829xe.L.c, viewTreeObserverOnGlobalLayoutListenerC2829xe.J, "vpr2");
                C2785wd c2785wd3 = new C2785wd((Context) eVarM.b, c2743ve, i, z2, (B7) c2743ve.a.L.c, c1668Bd, (Hk) eVarM.e);
                eVarM.f = c2785wd3;
                ((C2743ve) eVarM.d).addView(c2785wd3, 0, new ViewGroup.LayoutParams(-1, -1));
                ((C2785wd) eVarM.f).a(iA, iA2, iMin, iMin2);
                c2743ve.a.n.l = false;
            }
            C2785wd c2785wd4 = (C2785wd) eVarM.f;
            if (c2785wd4 != null) {
                b(c2785wd4, map);
                return;
            }
            return;
        }
        BinderC2915ze binderC2915zeP = interfaceC2529qe.p();
        if (binderC2915zeP != null) {
            if (str.equals("timeupdate")) {
                String str6 = (String) map.get("currentTime");
                if (str6 == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("currentTime parameter missing from timeupdate video GMSG.");
                    return;
                }
                try {
                    float f = Float.parseFloat(str6);
                    synchronized (binderC2915zeP.b) {
                        binderC2915zeP.j = f;
                    }
                    return;
                } catch (NumberFormatException unused4) {
                    com.google.android.gms.ads.internal.util.client.i.h("Could not parse currentTime parameter from timeupdate video GMSG: ".concat(str6));
                    return;
                }
            }
            if (str.equals("skip")) {
                synchronized (binderC2915zeP.b) {
                    z = binderC2915zeP.h;
                    i2 = binderC2915zeP.e;
                    binderC2915zeP.e = 3;
                }
                AbstractC2270kd.f.execute(new RunnableC2872ye(binderC2915zeP, i2, 3, z, z));
                return;
            }
        }
        C2785wd c2785wd5 = (C2785wd) eVarM.f;
        if (c2785wd5 == null) {
            HashMap map5 = new HashMap();
            map5.put("event", "no_video_view");
            interfaceC2529qe.j("onVideoEvent", map5);
            return;
        }
        if (str.equals("click")) {
            Context context2 = interfaceC2529qe.getContext();
            int iA5 = a(context2, map, "x", 0);
            float fA = a(context2, map, "y", 0);
            long jUptimeMillis = SystemClock.uptimeMillis();
            MotionEvent motionEventObtain = MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 0, iA5, fA, 0);
            AbstractC2656td abstractC2656td2 = c2785wd5.g;
            if (abstractC2656td2 != null) {
                abstractC2656td2.dispatchTouchEvent(motionEventObtain);
            }
            motionEventObtain.recycle();
            return;
        }
        if (str.equals("currentTime")) {
            String str7 = (String) map.get("time");
            if (str7 == null) {
                com.google.android.gms.ads.internal.util.client.i.h("Time parameter missing from currentTime video GMSG.");
                return;
            }
            try {
                int i3 = (int) (Float.parseFloat(str7) * 1000.0f);
                AbstractC2656td abstractC2656td3 = c2785wd5.g;
                if (abstractC2656td3 == null) {
                    return;
                }
                abstractC2656td3.v(i3);
                return;
            } catch (NumberFormatException unused5) {
                com.google.android.gms.ads.internal.util.client.i.h("Could not parse time parameter from currentTime video GMSG: ".concat(str7));
                return;
            }
        }
        if (str.equals("hide")) {
            c2785wd5.setVisibility(4);
            return;
        }
        if (str.equals("remove")) {
            c2785wd5.setVisibility(8);
            return;
        }
        if (str.equals("load")) {
            AbstractC2656td abstractC2656td4 = c2785wd5.g;
            if (abstractC2656td4 == null) {
                return;
            }
            if (TextUtils.isEmpty(c2785wd5.n)) {
                c2785wd5.c("no_src", new String[0]);
                return;
            } else {
                abstractC2656td4.f(c2785wd5.n, c2785wd5.o, numValueOf);
                return;
            }
        }
        if (str.equals("loadControl")) {
            b(c2785wd5, map);
            return;
        }
        if (str.equals("muted")) {
            if (Boolean.parseBoolean((String) map.get("muted"))) {
                AbstractC2656td abstractC2656td5 = c2785wd5.g;
                if (abstractC2656td5 == null) {
                    return;
                }
                C1686Ed c1686Ed = abstractC2656td5.b;
                c1686Ed.e = true;
                c1686Ed.a();
                abstractC2656td5.m();
                return;
            }
            AbstractC2656td abstractC2656td6 = c2785wd5.g;
            if (abstractC2656td6 == null) {
                return;
            }
            C1686Ed c1686Ed2 = abstractC2656td6.b;
            c1686Ed2.e = false;
            c1686Ed2.a();
            abstractC2656td6.m();
            return;
        }
        if (str.equals("pause")) {
            AbstractC2656td abstractC2656td7 = c2785wd5.g;
            if (abstractC2656td7 == null) {
                return;
            }
            abstractC2656td7.t();
            return;
        }
        if (str.equals("play")) {
            AbstractC2656td abstractC2656td8 = c2785wd5.g;
            if (abstractC2656td8 == null) {
                return;
            }
            abstractC2656td8.u();
            return;
        }
        if (str.equals("show")) {
            c2785wd5.setVisibility(0);
            return;
        }
        if (str.equals("src")) {
            String str8 = (String) map.get("src");
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e2)).booleanValue() && TextUtils.isEmpty(str8)) {
                com.google.android.gms.ads.internal.util.client.i.h("Src parameter missing from src video GMSG.");
                return;
            }
            if (map.containsKey("periodicReportIntervalMs")) {
                try {
                    numValueOf2 = Integer.valueOf(Integer.parseInt((String) map.get("periodicReportIntervalMs")));
                } catch (NumberFormatException unused6) {
                    com.google.android.gms.ads.internal.util.client.i.h("Video gmsg invalid numeric parameter 'periodicReportIntervalMs': ".concat(String.valueOf((String) map.get("periodicReportIntervalMs"))));
                }
            }
            String[] strArr = {str8};
            String str9 = (String) map.get("demuxed");
            if (str9 != null) {
                try {
                    JSONArray jSONArray = new JSONArray(str9);
                    ArrayList arrayList = new ArrayList();
                    for (int i4 = 0; i4 < jSONArray.length(); i4++) {
                        String string = jSONArray.getString(i4);
                        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e2)).booleanValue() || !TextUtils.isEmpty(string)) {
                            arrayList.add(string);
                        }
                    }
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e2)).booleanValue() && arrayList.isEmpty()) {
                        com.google.android.gms.ads.internal.util.client.i.h("All demuxed URLs are empty for playback: " + str9);
                        return;
                    }
                    strArr = (String[]) arrayList.toArray(new String[arrayList.size()]);
                } catch (JSONException unused7) {
                    com.google.android.gms.ads.internal.util.client.i.h("Malformed demuxed URL list for playback: ".concat(str9));
                    strArr = new String[]{str8};
                }
            }
            if (numValueOf2 != null) {
                interfaceC2529qe.q0(numValueOf2.intValue());
            }
            c2785wd5.n = str8;
            c2785wd5.o = strArr;
            return;
        }
        if (str.equals("touchMove")) {
            Context context3 = interfaceC2529qe.getContext();
            int iA6 = a(context3, map, "dx", 0);
            int iA7 = a(context3, map, "dy", 0);
            float f2 = iA6;
            float f3 = iA7;
            AbstractC2656td abstractC2656td9 = c2785wd5.g;
            if (abstractC2656td9 != null) {
                abstractC2656td9.z(f2, f3);
            }
            if (this.a) {
                return;
            }
            interfaceC2529qe.R();
            this.a = true;
            return;
        }
        if (!str.equals("volume")) {
            if (str.equals("watermark")) {
                c2785wd5.k();
                return;
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("Unknown video action: ".concat(str));
                return;
            }
        }
        String str10 = (String) map.get("volume");
        if (str10 == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Level parameter missing from volume video GMSG.");
            return;
        }
        try {
            float f4 = Float.parseFloat(str10);
            AbstractC2656td abstractC2656td10 = c2785wd5.g;
            if (abstractC2656td10 == null) {
                return;
            }
            C1686Ed c1686Ed3 = abstractC2656td10.b;
            c1686Ed3.f = f4;
            c1686Ed3.a();
            abstractC2656td10.m();
        } catch (NumberFormatException unused8) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not parse volume parameter from volume video GMSG: ".concat(str10));
        }
    }
}
