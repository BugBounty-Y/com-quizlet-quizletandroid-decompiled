package com.google.android.gms.ads.internal;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Base64;
import android.view.MotionEvent;
import androidx.compose.foundation.gestures.l1;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.internal.util.C;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2096gb;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BinderC2408nm;
import com.google.android.gms.internal.ads.Bq;
import com.google.android.gms.internal.ads.C1673Cc;
import com.google.android.gms.internal.ads.C1849aq;
import com.google.android.gms.internal.ads.C1920ca;
import com.google.android.gms.internal.ads.C1923cd;
import com.google.android.gms.internal.ads.C2007ea;
import com.google.android.gms.internal.ads.C2067fq;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2257k6;
import com.google.android.gms.internal.ads.C2280kn;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.C2429o6;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2708um;
import com.google.android.gms.internal.ads.C2711up;
import com.google.android.gms.internal.ads.C2755vq;
import com.google.android.gms.internal.ads.C2830xf;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.D9;
import com.google.android.gms.internal.ads.Ej;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Fv;
import com.google.android.gms.internal.ads.Gj;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2139ha;
import com.google.android.gms.internal.ads.InterfaceC2183ia;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.InterfaceC2751vm;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Nv;
import com.google.android.gms.internal.ads.Ol;
import com.google.android.gms.internal.ads.Or;
import com.google.android.gms.internal.ads.Os;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Qg;
import com.google.android.gms.internal.ads.SharedPreferencesOnSharedPreferenceChangeListenerC2687u7;
import com.google.android.gms.internal.ads.Tv;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.zzbvl;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Fv {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;

    public /* synthetic */ c(l1 l1Var, Long l, Hk hk, Pq pq, Uq uq) {
        this.a = 0;
        this.b = l;
        this.c = hk;
        this.d = pq;
        this.e = uq;
    }

    public C2313ld a(Object obj) {
        C2313ld c2313ld = new C2313ld();
        C1920ca c1920caN = ((C2007ea) this.d).n();
        A.l("callJs > getEngine: Promise created");
        c1920caN.u(new com.quizlet.data.repository.user.e(this, c1920caN, obj, c2313ld), new Fi(8, c2313ld, c1920caN));
        return c2313ld;
    }

    @Override // com.google.android.gms.internal.ads.Fv
    public final com.google.common.util.concurrent.e b(Object obj) throws JSONException {
        com.google.common.util.concurrent.e eVarC;
        Tv tvE;
        switch (this.a) {
            case 0:
                Long l = (Long) this.b;
                Hk hk = (Hk) this.c;
                Pq pq = (Pq) this.d;
                Uq uq = (Uq) this.e;
                JSONObject jSONObject = (JSONObject) obj;
                boolean zOptBoolean = jSONObject.optBoolean("isSuccessful", false);
                if (zOptBoolean) {
                    String string = jSONObject.getString("appSettingsJson");
                    j jVar = j.C;
                    C cD = jVar.h.d();
                    cD.l();
                    synchronized (cD.a) {
                        try {
                            jVar.k.getClass();
                            long jCurrentTimeMillis = System.currentTimeMillis();
                            if (string == null || string.equals(cD.n.e)) {
                                cD.n.f = jCurrentTimeMillis;
                            } else {
                                cD.n = new C1923cd(string, jCurrentTimeMillis);
                                SharedPreferences.Editor editor = cD.g;
                                if (editor != null) {
                                    editor.putString("app_settings_json", string);
                                    cD.g.putLong("app_settings_last_update_ms", jCurrentTimeMillis);
                                    cD.g.apply();
                                }
                                cD.m();
                                Iterator it2 = cD.c.iterator();
                                while (it2.hasNext()) {
                                    ((Runnable) it2.next()).run();
                                }
                            }
                        } finally {
                        }
                    }
                    if (l != null) {
                        j.C.k.getClass();
                        l1.J(hk, "cld_s", SystemClock.elapsedRealtime() - l.longValue());
                    }
                }
                String strOptString = jSONObject.optString("errorMessage", "");
                if (!TextUtils.isEmpty(strOptString)) {
                    pq.A(strOptString);
                }
                pq.h(zOptBoolean);
                uq.b(pq.l());
                return Tv.b;
            case 1:
                return a(obj);
            case 2:
                MotionEvent motionEvent = (MotionEvent) this.e;
                int iIntValue = ((Integer) obj).intValue();
                Uri.Builder builder = (Uri.Builder) this.c;
                if (iIntValue != 1) {
                    builder.appendQueryParameter((String) r.d.c.a(AbstractC2773w7.ja), "10");
                    return AbstractC2025es.E(builder.toString());
                }
                Uri.Builder builderBuildUpon = builder.build().buildUpon();
                C2601s7 c2601s7 = AbstractC2773w7.ka;
                r rVar = r.d;
                builderBuildUpon.appendQueryParameter((String) rVar.c.a(c2601s7), "1");
                C2601s7 c2601s72 = AbstractC2773w7.ja;
                SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
                builderBuildUpon.appendQueryParameter((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72), "12");
                if (((String) this.d).contains((CharSequence) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.la))) {
                    builderBuildUpon.authority((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.ma));
                }
                C2830xf c2830xf = (C2830xf) this.b;
                C2708um c2708um = c2830xf.c;
                Uri uriBuild = builderBuildUpon.build();
                c2708um.getClass();
                try {
                    androidx.privacysandbox.ads.adservices.java.measurement.h hVar = c2708um.a;
                    Objects.requireNonNull(hVar);
                    eVarC = hVar.d(uriBuild, motionEvent);
                } catch (Exception e) {
                    eVarC = AbstractC2025es.C(e);
                }
                return AbstractC2025es.N(Nv.t(eVarC), new D9(builder, 2), c2830xf.f);
            case 3:
                L9 l9 = j.C.d;
                Gj gj = (Gj) this.b;
                InterfaceC2529qe interfaceC2529qeG = L9.g((Context) gj.a, (androidx.work.impl.model.c) gj.e, new com.bumptech.glide.load.engine.cache.f(0, 0, 0), (VersionInfoParcel) gj.d, (P4) gj.c, (C2429o6) gj.f, null, (Hk) gj.m, (BinderC2408nm) gj.p, null, null, null, (C2067fq) gj.q, "native-omid", false, false);
                C2257k6 c2257k6 = new C2257k6(interfaceC2529qeG);
                interfaceC2529qeG.L().g = new Ej(c2257k6);
                interfaceC2529qeG.loadData(Base64.encodeToString(((String) this.c).getBytes(), 1), "text/html", "base64");
                if (((Boolean) r.d.c.a(AbstractC2773w7.rd)).booleanValue()) {
                    C1673Cc c1673Cc = (C1673Cc) this.d;
                    if (c1673Cc != null) {
                        interfaceC2529qeG.L().y = c1673Cc;
                    }
                    interfaceC2529qeG.L().w = (a) this.e;
                }
                return c2257k6;
            case 4:
                return AbstractC2025es.N(((Ol) this.c).d((zzbvl) this.d), (Fv) this.e, (C2227jd) ((C2326lq) this.b).b);
            case 5:
                C2280kn c2280kn = (C2280kn) this.b;
                Pq pqF = LA.f(c2280kn.j, 12);
                Vp vp = (Vp) this.c;
                pqF.I(vp.E);
                pqF.zzi();
                InterfaceC2751vm interfaceC2751vm = (InterfaceC2751vm) this.e;
                C1849aq c1849aq = (C1849aq) this.d;
                com.google.common.util.concurrent.e eVarO = AbstractC2025es.O(interfaceC2751vm.b(c1849aq, vp), vp.R, TimeUnit.MILLISECONDS, c2280kn.f);
                c2280kn.h.a(c1849aq, vp, eVarO, c2280kn.c);
                AbstractC2096gb.L(eVarO, c2280kn.k, pqF, false);
                return eVarO;
            default:
                Or or = (Or) this.b;
                Os os = (Os) this.c;
                C2326lq c2326lq = (C2326lq) this.d;
                C2711up c2711up = (C2711up) this.e;
                C2755vq c2755vq = (C2755vq) obj;
                synchronized (or) {
                    try {
                        or.b = true;
                        c2755vq.a = (Qg) ((C2881yn) os.b).b;
                        if (or.a) {
                            tvE = AbstractC2025es.E(new Bq(c2755vq, c2711up));
                        } else {
                            c2326lq.v(c2711up.g, c2755vq);
                            tvE = Tv.b;
                        }
                    } finally {
                    }
                }
                return tvE;
        }
    }

    public c(C2007ea c2007ea, String str, InterfaceC2183ia interfaceC2183ia, InterfaceC2139ha interfaceC2139ha) {
        this.a = 1;
        this.d = c2007ea;
        this.e = str;
        this.c = interfaceC2183ia;
        this.b = interfaceC2139ha;
    }

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }
}
