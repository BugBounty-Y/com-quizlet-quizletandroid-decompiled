package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.MotionEvent;
import android.view.ViewGroup;
import androidx.compose.material3.C0591b1;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.util.zzbb;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1653c;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class Fi implements M, InterfaceC1653c, InterfaceC2356md, Pv, InterfaceC2589rw, InterfaceC2517q8, InterfaceC1681De, Hq, Ep, Xh {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ Fi() {
        this.a = 3;
    }

    private final void i(Throwable th) {
    }

    private final void k(Throwable th) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public void A(String str, int i, String str2, boolean z) {
        HashMap map = new HashMap();
        map.put("messageType", "validatorHtmlLoaded");
        map.put("id", (String) ((Map) this.c).get("id"));
        ((C2662tj) this.b).b.b(map);
    }

    public void B(int i, int i2, int i3, int i4) throws JSONException {
        try {
            ((InterfaceC2529qe) this.b).b("onSizeChanged", new JSONObject().put("x", i).put("y", i2).put(OTUXParamsKeys.OT_UX_WIDTH, i3).put(OTUXParamsKeys.OT_UX_HEIGHT, i4));
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching size change.", e);
        }
    }

    public void C(String str) throws JSONException {
        try {
            ((InterfaceC2529qe) this.b).b("onStateChanged", new JSONObject().put("state", str));
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching state change.", e);
        }
    }

    public void D(C1740Nd c1740Nd) {
        Handler handler = (Handler) this.b;
        if (handler != null) {
            handler.post(new Qv(1, this, c1740Nd));
        }
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [android.view.View$OnClickListener, com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    public void a() {
        Bu bu = ViewTreeObserverOnGlobalLayoutListenerC2148hj.p;
        ?? r1 = (AbstractBinderC2814x5) this.b;
        Map mapL = r1.l();
        if (mapL == null) {
            return;
        }
        int i = bu.d;
        int i2 = 0;
        while (i2 < i) {
            Object obj = mapL.get((String) bu.get(i2));
            i2++;
            if (obj != null) {
                r1.onClick((ViewGroup) this.c);
                return;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        Iq iq = (Iq) this.b;
        ((Mq) obj).d((Jq) iq.a, iq.b, (Throwable) this.c);
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Bundle bundle;
        switch (this.a) {
            case 11:
                ((InterfaceC2399nd) this.b).mo21b(obj);
                return;
            case 14:
                List list = ((C2531qg) obj).a;
                com.quizlet.remote.model.notes.e eVar = (com.quizlet.remote.model.notes.e) this.b;
                C2659tg c2659tg = (C2659tg) this.c;
                Xv xv = c2659tg.a;
                if (list == null || list.isEmpty()) {
                    xv.execute(new RunnableC2573rg(eVar, 0));
                    return;
                }
                com.google.common.util.concurrent.e eVarN = Tv.b;
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    eVarN = AbstractC2025es.N(AbstractC2025es.A(eVarN, Throwable.class, new D9(eVar, 3), xv), new C2616sg(c2659tg, eVar, (com.google.common.util.concurrent.e) it2.next(), 0), xv);
                }
                eVarN.a(new Qv(0, eVarN, new C1732Mb(c2659tg, false, eVar, 17)), xv);
                return;
            case 18:
                ((InterfaceC2529qe) obj).F0((String) this.b, (InterfaceC2389n9) this.c);
                return;
            case 20:
                ((C2150hl) obj).n = true;
                ((BinderC2707ul) this.c).d.b((String) this.b);
                return;
            case 21:
                ParcelFileDescriptor parcelFileDescriptor = (ParcelFileDescriptor) obj;
                try {
                    C2601s7 c2601s7 = AbstractC2773w7.h2;
                    com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                    boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
                    InterfaceC1792Wb interfaceC1792Wb = (InterfaceC1792Wb) this.c;
                    if (!zBooleanValue) {
                        interfaceC1792Wb.a2(parcelFileDescriptor);
                        return;
                    }
                    boolean zBooleanValue2 = ((Boolean) rVar.c.a(AbstractC2773w7.i2)).booleanValue();
                    zzbvl zzbvlVar = (zzbvl) this.b;
                    if (zBooleanValue2 && (bundle = zzbvlVar.m) != null) {
                        com.google.android.gms.ads.internal.j.C.k.getClass();
                        bundle.putLong("binder-call-start", System.currentTimeMillis());
                    }
                    interfaceC1792Wb.m0(parcelFileDescriptor, zzbvlVar);
                    return;
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
            default:
                YF yf = (YF) this.c;
                synchronized (yf) {
                    yf.e = null;
                    ((ArrayDeque) yf.d).addFirst((C2711up) this.b);
                    if (yf.a == 1) {
                        yf.c();
                    }
                }
                return;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00e6  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0117 A[EDGE_INSN: B:67:0x0117->B:51:0x0117 BREAK  A[LOOP:1: B:39:0x00e0->B:50:0x0106], SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.M
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.L d(com.google.android.gms.internal.ads.P r17, long r18) {
        /*
            Method dump skipped, instructions count: 300
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Fi.d(com.google.android.gms.internal.ads.P, long):com.google.android.gms.internal.ads.L");
    }

    public void f(long j, Kn kn) {
        if (kn.s() < 9) {
            return;
        }
        int iU = kn.u();
        int iU2 = kn.u();
        int iZ = kn.z();
        if (iU == 434 && iU2 == 1195456820 && iZ == 3) {
            LA.r(j, kn, (InterfaceC2380n0[]) this.c);
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) {
        synchronized (((com.bumptech.glide.manager.p) this.c).c) {
            ((C2257k6) this.b).d(new RuntimeException("Connection failed."));
        }
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [android.view.View$OnTouchListener, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    public void g(MotionEvent motionEvent) {
        ((AbstractBinderC2814x5) this.b).onTouch(null, motionEvent);
    }

    public void h(Gq gq) {
        Q4 q4 = new Q4((Zl) this.b, 5);
        C2227jd c2227jd = (C2227jd) ((Xv) this.c);
        com.google.common.util.concurrent.e eVarD = c2227jd.d(q4);
        eVarD.a(new Qv(0, eVarD, new Ts(gq, 24)), c2227jd);
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public Object j() {
        Qg qg;
        synchronized (this) {
            qg = (Qg) this.c;
        }
        return qg;
    }

    public synchronized com.google.common.util.concurrent.e l(Fp fp, Dp dp, Qg qg) {
        zzbvl zzbvlVar;
        this.c = qg;
        if (qg == null || (zzbvlVar = (zzbvl) fp.b) == null) {
            return ((C2883yp) this.b).g(fp, dp, qg);
        }
        C2831xg c2831xgZzb = qg.zzb();
        return c2831xgZzb.a(c2831xgZzb.c(AbstractC2025es.E(zzbvlVar)));
    }

    public void m(int i, int i2, long j, Long l, String str, Ar ar) {
        Fi fiA = ((Hk) this.b).a();
        fiA.o("plaac_ts", Long.toString(j));
        fiA.o("app", (String) this.c);
        fiA.o("ad_format", ar.a());
        fiA.o("ad_unit_id", ar.a);
        fiA.o("max_ads", Integer.toString(i));
        fiA.o("cache_size", Integer.toString(i2));
        fiA.o("action", "is_ad_available");
        if (l != null) {
            fiA.o("plaay_ts", Long.toString(l.longValue()));
        }
        if (str != null) {
            fiA.o("gqi", str);
        }
        fiA.x();
    }

    public void n(W w, C0591b1 c0591b1) {
        int i = 0;
        while (true) {
            InterfaceC2380n0[] interfaceC2380n0Arr = (InterfaceC2380n0[]) this.c;
            if (i >= interfaceC2380n0Arr.length) {
                return;
            }
            c0591b1.b();
            c0591b1.c();
            InterfaceC2380n0 interfaceC2380n0Q = w.q(c0591b1.c, 3);
            C1832aG c1832aG = (C1832aG) ((List) this.b).get(i);
            String str = c1832aG.m;
            boolean z = true;
            if (!"application/cea-608".equals(str) && !"application/cea-708".equals(str)) {
                z = false;
            }
            AbstractC1795We.G(z, "Invalid closed caption MIME type provided: ".concat(String.valueOf(str)));
            EF ef = new EF();
            c0591b1.c();
            ef.a = (String) c0591b1.e;
            ef.a("video/mp2t");
            ef.d(str);
            ef.e = c1832aG.e;
            ef.d = c1832aG.d;
            ef.G = c1832aG.H;
            ef.o = c1832aG.p;
            interfaceC2380n0Q.a(new C1832aG(ef));
            interfaceC2380n0Arr[i] = interfaceC2380n0Q;
            i++;
        }
    }

    public void o(String str, String str2) {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            return;
        }
        ((ConcurrentHashMap) this.b).put(str, str2);
    }

    public void p(Vp vp) {
        o("aai", vp.w);
        o("request_id", vp.n0);
        o("ad_format", Vp.a(vp.b));
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* bridge */ /* synthetic */ com.google.common.util.concurrent.e q(Fp fp, Dp dp) {
        return l(fp, dp, null);
    }

    public Set r(Kg kg) {
        return Collections.singleton(new C2318li(kg, AbstractC2270kd.g));
    }

    public void s(long j, int i, int i2, String str, Ar ar) {
        Fi fiA = ((Hk) this.b).a();
        fiA.o("ppla_ts", Long.toString(j));
        fiA.o("app", (String) this.c);
        fiA.o("ad_format", ar.a());
        fiA.o("ad_unit_id", ar.a);
        fiA.o("max_ads", Integer.toString(i));
        fiA.o("cache_size", Integer.toString(i2));
        fiA.o("action", "poll_ad");
        if (str != null) {
            fiA.o("gqi", str);
        }
        fiA.x();
    }

    public Set t(Kg kg) {
        return Collections.singleton(new C2318li(kg, AbstractC2270kd.g));
    }

    public void u(String str) throws JSONException {
        try {
            JSONObject jSONObjectPut = new JSONObject().put("message", str).put("action", (String) this.c);
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
            if (interfaceC2529qe != null) {
                interfaceC2529qe.b("onError", jSONObjectPut);
            }
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching error event.", e);
        }
    }

    public void v(EnumMap enumMap, long j) {
        Fi fiA = ((Hk) this.b).a();
        fiA.o("action", "start_preload");
        fiA.o("sp_ts", Long.toString(j));
        fiA.o("app", (String) this.c);
        for (com.google.android.gms.ads.c cVar : enumMap.keySet()) {
            String strValueOf = String.valueOf(cVar.name().toLowerCase(Locale.ENGLISH));
            fiA.o(strValueOf.concat("_count"), Integer.toString(((Integer) enumMap.get(cVar)).intValue()));
        }
        fiA.x();
    }

    public void w(int i, long j, Ar ar) {
        Fi fiA = ((Hk) this.b).a();
        fiA.o("action", "start_preload");
        fiA.o("sp_ts", Long.toString(j));
        fiA.o("app", (String) this.c);
        fiA.o("ad_format", ar.a());
        fiA.o("ad_unit_id", ar.a);
        fiA.o("max_ads", Integer.toString(i));
        fiA.x();
    }

    public void x() {
        ((Hk) this.c).b.execute(new Fk(this, 0));
    }

    public void y(int i, int i2, int i3, int i4, float f, int i5) {
        try {
            ((InterfaceC2529qe) this.b).b("onScreenInfoChanged", new JSONObject().put(OTUXParamsKeys.OT_UX_WIDTH, i).put(OTUXParamsKeys.OT_UX_HEIGHT, i2).put("maxSizeWidth", i3).put("maxSizeHeight", i4).put("density", f).put("rotation", i5));
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while obtaining screen information.", e);
        }
    }

    public void z(String str, String str2, long j, int i, int i2, String str3, Ar ar) {
        Fi fiA = ((Hk) this.b).a();
        fiA.o(str2, Long.toString(j));
        fiA.o("app", (String) this.c);
        fiA.o("ad_unit_id", ar.a);
        fiA.o("ad_format", ar.a());
        if (str != null) {
            fiA.o("action", str);
        }
        if (str3 != null) {
            fiA.o("gqi", str3);
        }
        if (i >= 0) {
            fiA.o("max_ads", Integer.toString(i));
        }
        if (i2 >= 0) {
            fiA.o("cache_size", Integer.toString(i2));
        }
        fiA.x();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza */
    public Fw mo22zza() {
        AtomicInteger atomicInteger = C2143he.u;
        Fw fwMo22zza = ((InterfaceC2589rw) this.b).mo22zza();
        byte[] bArr = (byte[]) this.c;
        return new C2055fe(new C1898bv(bArr), bArr.length, fwMo22zza);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    public JSONObject zzb() {
        return ((AbstractBinderC2814x5) this.b).o();
    }

    public /* synthetic */ Fi(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.google.android.gms.internal.ads.M
    /* renamed from: zzb, reason: collision with other method in class */
    public void mo14zzb() {
        byte[] bArr = Yo.b;
        int length = bArr.length;
        ((Kn) this.c).h(0, bArr);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public Fi(InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj, ViewGroup viewGroup) {
        this.a = 16;
        this.b = (AbstractBinderC2814x5) interfaceViewOnClickListenerC2705uj;
        this.c = viewGroup;
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2517q8
    /* renamed from: zza, reason: collision with other method in class */
    public JSONObject mo12zza() {
        return ((AbstractBinderC2814x5) this.b).x();
    }

    public Fi(C2883yp c2883yp) {
        this.a = 24;
        this.b = c2883yp;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2356md, com.google.android.gms.internal.ads.Hq
    /* renamed from: zza, reason: collision with other method in class */
    public void mo13zza() {
        switch (this.a) {
            case 8:
                com.google.android.gms.ads.internal.util.A.l("callJs > getEngine: Promise rejected");
                ((C2313ld) this.b).d(new zzboc("Unable to obtain a JavascriptEngine."));
                ((C1920ca) this.c).v();
                break;
            default:
                D7 d7 = (D7) ((Qm) this.b).d;
                C7 c7 = (C7) this.c;
                Parcel parcelF3 = d7.f3();
                AbstractC2857y5.e(parcelF3, c7);
                d7.d4(1, parcelF3);
                break;
        }
    }

    public Fi(C2326lq c2326lq) {
        this.a = 29;
        this.c = c2326lq;
    }

    public /* synthetic */ Fi(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj;
    }

    public Fi(Context context, Hk hk) {
        CharSequence charSequenceB;
        this.a = 28;
        this.b = hk;
        com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
        try {
            charSequenceB = com.google.android.gms.common.wrappers.c.a(context).b(context.getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.i.i("Failed to get application name", e);
            charSequenceB = "";
        }
        this.c = charSequenceB.toString();
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        String message;
        switch (this.a) {
            case 11:
                ((InterfaceC2356md) this.c).mo13zza();
                return;
            case 14:
                ((com.quizlet.remote.model.notes.e) this.b).zza(th);
                AbstractC2270kd.f.execute(new RunnableC1989e((C2659tg) this.c, 25));
                return;
            case 18:
            case 20:
                return;
            case 21:
                try {
                    InterfaceC1792Wb interfaceC1792Wb = (InterfaceC1792Wb) this.c;
                    zze zzeVarA = AbstractC1972di.a(th);
                    if (AbstractC2543qs.i(th.getMessage())) {
                        message = zzeVarA.b;
                    } else {
                        message = th.getMessage();
                    }
                    interfaceC1792Wb.d1(new zzbb(message, zzeVarA.a));
                    return;
                } catch (RemoteException unused) {
                    com.google.android.gms.ads.internal.util.A.m();
                    return;
                }
            default:
                YF yf = (YF) this.c;
                synchronized (yf) {
                    yf.e = null;
                }
                return;
        }
    }

    public Fi(Handler handler, SurfaceHolderCallbackC2091gD surfaceHolderCallbackC2091gD) {
        this.a = 1;
        if (surfaceHolderCallbackC2091gD != null) {
            handler.getClass();
        } else {
            handler = null;
        }
        this.b = handler;
        this.c = surfaceHolderCallbackC2091gD;
    }

    public Fi(Hk hk) {
        this.a = 19;
        this.c = hk;
        this.b = new ConcurrentHashMap();
    }

    public /* synthetic */ Fi(Eo eo) {
        this.a = 4;
        this.b = eo;
        this.c = new Kn();
    }

    public Fi(Bu bu, int[] iArr) {
        this.a = 27;
        this.b = AbstractC2330lu.n(bu);
        this.c = iArr;
    }

    public Fi(List list) {
        this.a = 5;
        this.b = list;
        this.c = new InterfaceC2380n0[list.size()];
    }
}
