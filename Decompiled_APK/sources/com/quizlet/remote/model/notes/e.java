package com.quizlet.remote.model.notes;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.HandlerThread;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import androidx.appcompat.widget.C0122z;
import androidx.compose.ui.text.AbstractC0996h;
import androidx.compose.ui.text.C0985e;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.L;
import androidx.compose.ui.text.p;
import androidx.compose.ui.text.r;
import androidx.compose.ui.text.s;
import androidx.compose.ui.text.t;
import androidx.datastore.core.C1087t;
import androidx.paging.C1309d;
import androidx.paging.C1313f;
import androidx.paging.C1315g;
import androidx.recyclerview.widget.C1372j;
import com.android.billingclient.api.h;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.nonagon.signalgeneration.i;
import com.google.android.gms.ads.nonagon.signalgeneration.q;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.InterfaceC1652b;
import com.google.android.gms.common.internal.InterfaceC1653c;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC2359mg;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C1759Qe;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1864b4;
import com.google.android.gms.internal.ads.C2084g6;
import com.google.android.gms.internal.ads.C2305lB;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.C2384n4;
import com.google.android.gms.internal.ads.C2743ve;
import com.google.android.gms.internal.ads.C2831xg;
import com.google.android.gms.internal.ads.C2886ys;
import com.google.android.gms.internal.ads.C2929zs;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.IA;
import com.google.android.gms.internal.ads.InterfaceC1769Sc;
import com.google.android.gms.internal.ads.Lh;
import com.google.android.gms.internal.ads.Ln;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.R7;
import com.google.android.gms.internal.ads.RunnableC2573rg;
import com.google.android.gms.internal.ads.RunnableC2793wl;
import com.google.android.gms.internal.ads.S4;
import com.google.android.gms.internal.ads.Tq;
import com.google.android.gms.internal.ads.Uq;
import com.google.android.gms.internal.ads.Zg;
import com.google.android.gms.internal.ads.zzbyz;
import com.google.android.gms.internal.ads.zzfpd;
import com.google.android.gms.internal.ads.zzfpf;
import com.google.android.gms.internal.ads.zzgzh;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3367m2;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException;
import com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowNoInternetException;
import com.quizlet.generated.enums.EnumC4518s0;
import com.quizlet.quizletandroid.k;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.m;
import kotlin.text.D;
import kotlin.u;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.x0;
import kotlinx.coroutines.y0;
import okhttp3.C;
import okhttp3.F;
import okhttp3.I;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class e implements s, Pv, InterfaceC1652b, InterfaceC1653c {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
        this.e = obj5;
        this.f = obj;
    }

    public static final void e(e eVar) throws UniversalUploadFlowNoInternetException {
        if (!((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) eVar.d)).a().a) {
            throw new UniversalUploadFlowNoInternetException();
        }
    }

    public static final void f(e eVar, K k) throws UniversalUploadFlowException {
        I i = k.c;
        if (i == null) {
            throw new UniversalUploadFlowException(null);
        }
        Intrinsics.checkNotNullParameter(i, "<this>");
        if (!Intrinsics.b(com.google.android.gms.internal.mlkit_common.s.c(i), EnumC4518s0.UPLOAD_METER_REACHED.a())) {
            throw new UniversalUploadFlowException(null);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object g(com.quizlet.remote.model.notes.e r13, java.util.List r14, java.lang.String r15, kotlin.coroutines.jvm.internal.c r16) throws com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException {
        /*
            r1 = r16
            boolean r2 = r1 instanceof com.quizlet.remote.model.universaluploadflow.e
            if (r2 == 0) goto L15
            r2 = r1
            com.quizlet.remote.model.universaluploadflow.e r2 = (com.quizlet.remote.model.universaluploadflow.e) r2
            int r3 = r2.m
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L15
            int r3 = r3 - r4
            r2.m = r3
            goto L1a
        L15:
            com.quizlet.remote.model.universaluploadflow.e r2 = new com.quizlet.remote.model.universaluploadflow.e
            r2.<init>(r13, r1)
        L1a:
            java.lang.Object r1 = r2.k
            kotlin.coroutines.intrinsics.a r11 = kotlin.coroutines.intrinsics.a.a
            int r3 = r2.m
            r12 = 1
            if (r3 == 0) goto L33
            if (r3 != r12) goto L2b
            java.lang.String r0 = r2.j
            androidx.glance.appwidget.protobuf.Z.e(r1)
            goto L90
        L2b:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r1)
            throw r0
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r1)
            com.quizlet.generated.enums.u0 r1 = com.quizlet.generated.enums.EnumC4524u0.INITIAL_WAIT_MS
            int r1 = r1.a()
            java.lang.Object r1 = r14.get(r1)
            java.lang.Number r1 = (java.lang.Number) r1
            int r4 = r1.intValue()
            com.quizlet.generated.enums.u0 r1 = com.quizlet.generated.enums.EnumC4524u0.INTERVAL_MS
            int r1 = r1.a()
            java.lang.Object r1 = r14.get(r1)
            java.lang.Number r1 = (java.lang.Number) r1
            int r9 = r1.intValue()
            com.quizlet.generated.enums.u0 r1 = com.quizlet.generated.enums.EnumC4524u0.MAX_SERVER_ERROR_RETRIES
            int r1 = r1.a()
            java.lang.Object r1 = r14.get(r1)
            java.lang.Number r1 = (java.lang.Number) r1
            int r8 = r1.intValue()
            com.quizlet.generated.enums.u0 r1 = com.quizlet.generated.enums.EnumC4524u0.TOTAL_TIMEOUT_MS
            int r1 = r1.a()
            java.lang.Object r0 = r14.get(r1)
            java.lang.Number r0 = (java.lang.Number) r0
            int r0 = r0.intValue()
            kotlin.jvm.internal.H r7 = new kotlin.jvm.internal.H
            r7.<init>()
            long r0 = (long) r0
            com.quizlet.remote.model.universaluploadflow.f r3 = new com.quizlet.remote.model.universaluploadflow.f
            r10 = 0
            r5 = r13
            r6 = r15
            r3.<init>(r4, r5, r6, r7, r8, r9, r10)
            r2.j = r15
            r2.m = r12
            java.lang.Object r1 = kotlinx.coroutines.E.L(r0, r3, r2)
            if (r1 != r11) goto L8f
            return r11
        L8f:
            r0 = r15
        L90:
            kotlin.Unit r1 = (kotlin.Unit) r1
            if (r1 == 0) goto L95
            return r0
        L95:
            com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException r0 = new com.quizlet.data.exceptions.universaluploadflow.UniversalUploadFlowException
            java.lang.String r1 = "Polling timed out"
            r0.<init>(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.remote.model.notes.e.g(com.quizlet.remote.model.notes.e, java.util.List, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static e j(SharedPreferences sharedPreferences, ScheduledThreadPoolExecutor scheduledThreadPoolExecutor) {
        e eVar = new e(sharedPreferences, scheduledThreadPoolExecutor);
        synchronized (((ArrayDeque) eVar.e)) {
            try {
                ((ArrayDeque) eVar.e).clear();
                String string = ((SharedPreferences) eVar.b).getString((String) eVar.c, "");
                if (!TextUtils.isEmpty(string) && string.contains((String) eVar.d)) {
                    String[] strArrSplit = string.split((String) eVar.d, -1);
                    if (strArrSplit.length == 0) {
                        Log.e("FirebaseMessaging", "Corrupted queue. Please check the queue contents and item separator provided");
                    }
                    for (String str : strArrSplit) {
                        if (!TextUtils.isEmpty(str)) {
                            ((ArrayDeque) eVar.e).add(str);
                        }
                    }
                    return eVar;
                }
                return eVar;
            } finally {
            }
        }
    }

    public static C2384n4 s() {
        C1864b4 c1864b4W = C2384n4.W();
        c1864b4W.e();
        C2384n4.E((C2384n4) c1864b4W.b, 32768L);
        return (C2384n4) c1864b4W.c();
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void V(int i) throws InterruptedException {
        try {
            ((LinkedBlockingQueue) this.e).put(s());
        } catch (InterruptedException unused) {
        }
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1652b
    public void X() {
        C2929zs c2929zs;
        LinkedBlockingQueue linkedBlockingQueue = (LinkedBlockingQueue) this.e;
        HandlerThread handlerThread = (HandlerThread) this.f;
        try {
            c2929zs = (C2929zs) ((C2886ys) this.b).m();
        } catch (DeadObjectException | IllegalStateException unused) {
            c2929zs = null;
        }
        if (c2929zs != null) {
            try {
                try {
                    zzfpd zzfpdVar = new zzfpd(1, (String) this.c, (String) this.d);
                    Parcel parcelF3 = c2929zs.f3();
                    AbstractC2857y5.c(parcelF3, zzfpdVar);
                    Parcel parcelY3 = c2929zs.Y3(1, parcelF3);
                    zzfpf zzfpfVar = (zzfpf) AbstractC2857y5.a(parcelY3, zzfpf.CREATOR);
                    parcelY3.recycle();
                    if (zzfpfVar.b == null) {
                        try {
                            byte[] bArr = zzfpfVar.c;
                            IA ia = IA.a;
                            C2305lB c2305lB = C2305lB.c;
                            zzfpfVar.b = C2384n4.l0(bArr, IA.b);
                            zzfpfVar.c = null;
                        } catch (zzgzh | NullPointerException e) {
                            throw new IllegalStateException(e);
                        }
                    }
                    zzfpfVar.a();
                    linkedBlockingQueue.put(zzfpfVar.b);
                } catch (Throwable unused2) {
                    linkedBlockingQueue.put(s());
                }
            } catch (InterruptedException unused3) {
            } catch (Throwable th) {
                t();
                handlerThread.quit();
                throw th;
            }
            t();
            handlerThread.quit();
        }
    }

    @Override // androidx.compose.ui.text.s
    public boolean a() {
        ArrayList arrayList = (ArrayList) this.f;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            if (((r) arrayList.get(i)).a.a()) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @Override // androidx.compose.ui.text.s
    public float b() {
        return ((Number) this.d.getValue()).floatValue();
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        Tq tq;
        switch (this.a) {
            case 3:
                q qVar = (q) obj;
                Tq tqN4 = i.n4((com.google.common.util.concurrent.e) this.b, (zzbyz) this.c);
                i iVar = (i) this.f;
                iVar.C.set(true);
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E7)).booleanValue();
                Pq pq = (Pq) this.e;
                InterfaceC1769Sc interfaceC1769Sc = (InterfaceC1769Sc) this.d;
                if (!zBooleanValue) {
                    if (interfaceC1769Sc != null) {
                        try {
                            interfaceC1769Sc.C("QueryInfo generation has been disabled.");
                        } catch (RemoteException e) {
                            com.google.android.gms.ads.internal.util.client.i.e("QueryInfo generation has been disabled.".concat(e.toString()));
                        }
                    }
                    if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                        return;
                    }
                    pq.A("QueryInfo generation has been disabled.");
                    pq.h(false);
                    tqN4.a(pq);
                    tqN4.h();
                    return;
                }
                try {
                    try {
                        if (qVar == null) {
                            if (interfaceC1769Sc != null) {
                                interfaceC1769Sc.e1(null, null, null);
                            }
                            pq.h(true);
                            if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                                return;
                            }
                        } else {
                            try {
                                String str = qVar.a;
                                if (TextUtils.isEmpty((!TextUtils.isEmpty(qVar.c) ? new JSONObject(qVar.c) : new JSONObject(qVar.b)).optString("request_id", ""))) {
                                    com.google.android.gms.ads.internal.util.client.i.h("The request ID is empty in request JSON.");
                                    if (interfaceC1769Sc != null) {
                                        interfaceC1769Sc.C("Internal error: request ID is empty in request JSON.");
                                    }
                                    pq.A("Request ID empty");
                                    pq.h(false);
                                    if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                                        return;
                                    }
                                } else {
                                    Bundle bundle = qVar.f;
                                    boolean z = iVar.q;
                                    String str2 = iVar.r;
                                    String str3 = iVar.s;
                                    if (z && bundle != null && bundle.getInt(str3, -1) == -1) {
                                        bundle.putInt(str3, iVar.t.get());
                                    }
                                    if (iVar.p && bundle != null && TextUtils.isEmpty(bundle.getString(str2))) {
                                        if (TextUtils.isEmpty(iVar.v)) {
                                            iVar.v = j.C.c.y(iVar.c, iVar.u.a);
                                        }
                                        bundle.putString(str2, iVar.v);
                                    }
                                    if (interfaceC1769Sc != null) {
                                        if (TextUtils.isEmpty(qVar.c)) {
                                            interfaceC1769Sc.e1(str, qVar.b, bundle);
                                        } else {
                                            interfaceC1769Sc.e1(str, qVar.c, bundle);
                                        }
                                    }
                                    pq.h(true);
                                    if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                                        return;
                                    }
                                }
                            } catch (JSONException e2) {
                                com.google.android.gms.ads.internal.util.client.i.h("Failed to create JSON object from the request string.");
                                if (interfaceC1769Sc != null) {
                                    interfaceC1769Sc.C("Internal error for request JSON: " + e2.toString());
                                }
                                pq.g(e2);
                                pq.h(false);
                                j.C.h.h("SignalGeneratorImpl.generateSignals.onSuccess", e2);
                                if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                                    return;
                                }
                            }
                        }
                    } catch (Throwable th) {
                        if (((Boolean) R7.e.o()).booleanValue() && tqN4 != null) {
                            tqN4.a(pq);
                            tqN4.h();
                        }
                        throw th;
                    }
                } catch (RemoteException e3) {
                    pq.g(e3);
                    pq.h(false);
                    com.google.android.gms.ads.internal.util.client.i.f("", e3);
                    j.C.h.h("SignalGeneratorImpl.generateSignals.onSuccess", e3);
                    if (!((Boolean) R7.e.o()).booleanValue() || tqN4 == null) {
                        return;
                    }
                }
                tqN4.a(pq);
                tqN4.h();
                return;
            default:
                C2084g6 c2084g6 = (C2084g6) this.f;
                AbstractC2359mg abstractC2359mg = (AbstractC2359mg) obj;
                synchronized (c2084g6) {
                    try {
                        ((Lh) abstractC2359mg.g.a.b).b = (Ln) ((C2326lq) c2084g6.c).c;
                        ((S4) this.b).o(abstractC2359mg);
                        ((C1765Re) c2084g6.b).a().execute(new RunnableC2573rg(this, 1));
                        if (!((Boolean) R7.c.o()).booleanValue() || (tq = (Tq) this.c) == null) {
                            Uq uq = (Uq) c2084g6.d;
                            Pq pq2 = (Pq) this.d;
                            pq2.f(abstractC2359mg.a.b);
                            pq2.I(abstractC2359mg.f.a);
                            pq2.h(true);
                            uq.b(pq2.l());
                        } else {
                            tq.g(abstractC2359mg.a.b);
                            tq.e(abstractC2359mg.f.a);
                            Pq pq3 = (Pq) this.d;
                            pq3.h(true);
                            tq.a(pq3);
                            tq.h();
                        }
                    } finally {
                    }
                }
                return;
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.Object, kotlin.k] */
    @Override // androidx.compose.ui.text.s
    public float d() {
        return ((Number) this.e.getValue()).floatValue();
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1653c
    public void f0(ConnectionResult connectionResult) throws InterruptedException {
        try {
            ((LinkedBlockingQueue) this.e).put(s());
        } catch (InterruptedException unused) {
        }
    }

    public void h(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        ((h) this.d).a(name, value);
    }

    public C i() {
        Map mapUnmodifiableMap;
        okhttp3.s sVar = (okhttp3.s) this.b;
        if (sVar == null) {
            throw new IllegalStateException("url == null");
        }
        String str = (String) this.c;
        okhttp3.r rVarD = ((h) this.d).d();
        F f = (F) this.e;
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.f;
        byte[] bArr = okhttp3.internal.b.a;
        Intrinsics.checkNotNullParameter(linkedHashMap, "<this>");
        if (linkedHashMap.isEmpty()) {
            mapUnmodifiableMap = V.c();
        } else {
            mapUnmodifiableMap = Collections.unmodifiableMap(new LinkedHashMap(linkedHashMap));
            Intrinsics.checkNotNullExpressionValue(mapUnmodifiableMap, "{\n    Collections.unmodi…(LinkedHashMap(this))\n  }");
        }
        return new C(sVar, str, rVarD, f, mapUnmodifiableMap);
    }

    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, java.util.Map] */
    public Enum k(Enum r8) {
        Object obj;
        kotlin.enums.a aVar;
        String str = (String) this.d;
        try {
            Object obj2 = ((com.quizlet.featuregate.contracts.growthbook.a) this.c).a.get(str);
            obj = null;
            aVar = obj2 instanceof kotlin.enums.a ? (kotlin.enums.a) obj2 : null;
        } catch (Exception e) {
            timber.log.c.a.q(e, "Unexpected error when checking growthbook feature: ".concat(str), new Object[0]);
        }
        if (aVar == null) {
            throw new IllegalArgumentException("Add missing enum mapping for configuration: ".concat(str));
        }
        Iterator<E> it2 = aVar.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Object next = it2.next();
            if (D.l(((Enum) next).name(), (String) ((u) this.f).getValue(), true)) {
                obj = next;
                break;
            }
        }
        Enum r4 = (Enum) obj;
        return r4 == null ? r8 : r4;
    }

    public void l(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        h hVar = (h) this.d;
        hVar.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        AbstractC3343g2.b(name);
        AbstractC3343g2.c(value, name);
        hVar.f(name);
        hVar.b(name, value);
    }

    public void m(long j, long j2, Set setIds) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        this.d = Long.valueOf(j);
        this.e = Long.valueOf(j2);
        ((J) this.c).d(setIds).q(com.quizlet.learn.checkpoint.data.a.a).u(new com.quizlet.analytics.marketing.e(this, 16), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c);
    }

    public void n(String method, F f) {
        Intrinsics.checkNotNullParameter(method, "method");
        if (method.length() <= 0) {
            throw new IllegalArgumentException("method.isEmpty() == true");
        }
        if (f == null) {
            Intrinsics.checkNotNullParameter(method, "method");
            if (method.equals("POST") || method.equals("PUT") || method.equals("PATCH") || method.equals("PROPPATCH") || method.equals("REPORT")) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.B("method ", method, " must have a request body.").toString());
            }
        } else if (!AbstractC3367m2.a(method)) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("method ", method, " must not have a request body.").toString());
        }
        this.c = method;
        this.e = f;
    }

    public void o(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        ((h) this.d).f(name);
    }

    public Object p(long j, kotlin.coroutines.jvm.internal.i iVar) throws Throwable {
        Object objJ = E.J((AbstractC5040y) this.c, new com.quizlet.features.setpage.studymodes.data.a(this, j, null), iVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }

    public void q(Class type, Object obj) {
        Intrinsics.checkNotNullParameter(type, "type");
        if (obj == null) {
            ((LinkedHashMap) this.f).remove(type);
            return;
        }
        if (((LinkedHashMap) this.f).isEmpty()) {
            this.f = new LinkedHashMap();
        }
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.f;
        Object objCast = type.cast(obj);
        Intrinsics.d(objCast);
        linkedHashMap.put(type, objCast);
    }

    public void r(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        if (D.r(url, "ws:", true)) {
            StringBuilder sb = new StringBuilder("http:");
            String strSubstring = url.substring(3);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
            sb.append(strSubstring);
            url = sb.toString();
        } else if (D.r(url, "wss:", true)) {
            StringBuilder sb2 = new StringBuilder("https:");
            String strSubstring2 = url.substring(4);
            Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String).substring(startIndex)");
            sb2.append(strSubstring2);
            url = sb2.toString();
        }
        Intrinsics.checkNotNullParameter(url, "<this>");
        C1372j c1372j = new C1372j();
        c1372j.l(null, url);
        okhttp3.s url2 = c1372j.d();
        Intrinsics.checkNotNullParameter(url2, "url");
        this.b = url2;
    }

    public void t() {
        C2886ys c2886ys = (C2886ys) this.b;
        if (c2886ys != null) {
            if (c2886ys.q() || c2886ys.r()) {
                c2886ys.e();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        Tq tq;
        switch (this.a) {
            case 3:
                String message = th.getMessage();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K7)).booleanValue()) {
                    j.C.h.g("SignalGeneratorImpl.generateSignals", th);
                } else {
                    j.C.h.h("SignalGeneratorImpl.generateSignals", th);
                }
                Tq tqN4 = i.n4((com.google.common.util.concurrent.e) this.b, (zzbyz) this.c);
                if (((Boolean) R7.e.o()).booleanValue() && tqN4 != null) {
                    Pq pq = (Pq) this.e;
                    pq.g(th);
                    pq.h(false);
                    tqN4.a(pq);
                    tqN4.h();
                }
                InterfaceC1769Sc interfaceC1769Sc = (InterfaceC1769Sc) this.d;
                if (interfaceC1769Sc != null) {
                    try {
                        if (!"Unknown format is no longer supported.".equals(message)) {
                            message = "Internal error. " + message;
                        }
                        interfaceC1769Sc.C(message);
                        break;
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.f("", e);
                        return;
                    }
                }
                break;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.L5)).booleanValue()) {
                    A.m();
                }
                C1759Qe c1759Qe = (C1759Qe) this.e;
                zze zzeVarL = AbstractC1972di.l(th, ((C2831xg) c1759Qe.t0.zzb()).l);
                ((Zg) c1759Qe.p0.zzb()).m0(zzeVarL);
                C2084g6 c2084g6 = (C2084g6) this.f;
                ((C1765Re) c2084g6.b).a().execute(new RunnableC2793wl(6, this, zzeVarL));
                AbstractC1795We.n(zzeVarL.a, "NativeAdLoader.onFailure", th);
                ((S4) this.b).zza();
                boolean zBooleanValue = ((Boolean) R7.c.o()).booleanValue();
                Pq pq2 = (Pq) this.d;
                if (zBooleanValue && (tq = (Tq) this.c) != null) {
                    tq.c(zzeVarL);
                    pq2.g(th);
                    pq2.h(false);
                    tq.a(pq2);
                    tq.h();
                    break;
                } else {
                    pq2.j(zzeVarL);
                    pq2.g(th);
                    pq2.h(false);
                    ((Uq) c2084g6.d).b(pq2.l());
                    break;
                }
                break;
        }
    }

    public /* synthetic */ e(boolean z) {
        this.a = 13;
    }

    public e(Context context, C2743ve c2743ve, C2743ve c2743ve2, Hk hk) {
        this.a = 4;
        this.b = context.getApplicationContext() != null ? context.getApplicationContext() : context;
        this.d = c2743ve;
        this.c = c2743ve2;
        this.f = null;
        this.e = hk;
    }

    public e(Context context, String str, String str2) {
        this.a = 6;
        this.c = str;
        this.d = str2;
        HandlerThread handlerThread = new HandlerThread("GassClient");
        this.f = handlerThread;
        handlerThread.start();
        C2886ys c2886ys = new C2886ys(9200000, context, handlerThread.getLooper(), this, this);
        this.b = c2886ys;
        this.e = new LinkedBlockingQueue();
        c2886ys.c();
    }

    public e(com.quizlet.data.repository.explanations.textbook.a termAndSelectedTermRepository, com.quizlet.data.repository.widget.b learnAnswerHistoryRepository, com.quizlet.data.repository.searchexplanations.c flashcardsAnswerHistoryRepository, androidx.compose.foundation.text.input.internal.u studyModeQuestionAttributeHistoryRepository, AbstractC5040y dispatcher) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(termAndSelectedTermRepository, "termAndSelectedTermRepository");
        Intrinsics.checkNotNullParameter(learnAnswerHistoryRepository, "learnAnswerHistoryRepository");
        Intrinsics.checkNotNullParameter(flashcardsAnswerHistoryRepository, "flashcardsAnswerHistoryRepository");
        Intrinsics.checkNotNullParameter(studyModeQuestionAttributeHistoryRepository, "studyModeQuestionAttributeHistoryRepository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = termAndSelectedTermRepository;
        this.d = learnAnswerHistoryRepository;
        this.e = flashcardsAnswerHistoryRepository;
        this.f = studyModeQuestionAttributeHistoryRepository;
        this.c = dispatcher;
    }

    public e(com.quizlet.infra.contracts.growthbook.a growthBook, com.quizlet.featuregate.contracts.growthbook.a enumMappings, String configurationName, Enum defaultValue) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(growthBook, "growthBook");
        Intrinsics.checkNotNullParameter(enumMappings, "enumMappings");
        Intrinsics.checkNotNullParameter(configurationName, "configurationName");
        Intrinsics.checkNotNullParameter(defaultValue, "defaultValue");
        this.b = growthBook;
        this.c = enumMappings;
        this.d = configurationName;
        this.e = defaultValue;
        this.f = l.b(new com.quizlet.featuregate.growthbook.a(this, 1));
    }

    public e(com.quizlet.remote.service.q service, AbstractC5040y dispatcher, org.slf4j.b logger, com.quizlet.data.repository.widget.b notesMapper, k artifactMapper) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(notesMapper, "notesMapper");
        Intrinsics.checkNotNullParameter(artifactMapper, "artifactMapper");
        this.b = service;
        this.c = dispatcher;
        this.d = logger;
        this.e = notesMapper;
        this.f = artifactMapper;
    }

    public e(com.quizlet.infra.legacysyncengine.managers.i saveManager, J termDataProvider) {
        this.a = 11;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        Intrinsics.checkNotNullParameter(termDataProvider, "termDataProvider");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = saveManager;
        this.c = termDataProvider;
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.f = dVarZ;
        Intrinsics.checkNotNullExpressionValue(new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0), "empty(...)");
    }

    public e(com.quizlet.remote.service.D service, AbstractC5040y dispatcher, com.quizlet.data.connectivity.a networkStatus, com.quizlet.quizletandroid.logging.initializer.a flashcardSetsMapper, C4636c questionCompatibilityHelper) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(flashcardSetsMapper, "flashcardSetsMapper");
        Intrinsics.checkNotNullParameter(questionCompatibilityHelper, "questionCompatibilityHelper");
        this.b = service;
        this.c = dispatcher;
        this.d = networkStatus;
        this.e = flashcardSetsMapper;
        this.f = questionCompatibilityHelper;
    }

    public e(InterfaceC4992i src, androidx.lifecycle.viewmodel.internal.a scope) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(src, "src");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.b = new C0122z(7, (byte) 0);
        d0 d0VarA = e0.a(1, SubsamplingScaleImageView.TILE_SIZE_AUTO, kotlinx.coroutines.channels.a.a);
        this.c = d0VarA;
        this.d = new x0(d0VarA, new C1315g(this, null));
        y0 y0VarA = E.A(scope, null, kotlinx.coroutines.D.b, new C1313f(src, this, null), 1);
        y0VarA.Q(new androidx.credentials.playservices.controllers.BeginSignIn.c(this, 6));
        this.e = y0VarA;
        this.f = new C1087t(new C1309d(this, null));
    }

    public e(C0995g c0995g, L l, List list, androidx.compose.ui.unit.b bVar, androidx.compose.ui.text.font.i iVar) {
        t tVar;
        String strSubstring;
        int i;
        int i2;
        C0995g c0995g2 = c0995g;
        L l2 = l;
        int i3 = 1;
        this.a = 1;
        this.b = c0995g2;
        this.c = list;
        m mVar = m.c;
        this.d = l.a(mVar, new p(this, i3));
        this.e = l.a(mVar, new p(this, 0));
        C0995g c0995g3 = AbstractC0996h.a;
        int length = c0995g2.a.length();
        List list2 = c0995g2.c;
        list2 = list2 == null ? kotlin.collections.K.a : list2;
        ArrayList arrayList = new ArrayList();
        int size = list2.size();
        int i4 = 0;
        int i5 = 0;
        while (true) {
            tVar = l2.b;
            if (i4 >= size) {
                break;
            }
            C0985e c0985e = (C0985e) list2.get(i4);
            t tVar2 = (t) c0985e.a;
            int i6 = c0985e.b;
            if (i6 != i5) {
                arrayList.add(new C0985e(tVar, i5, i6));
            }
            t tVarA = tVar.a(tVar2);
            int i7 = c0985e.c;
            arrayList.add(new C0985e(tVarA, i6, i7));
            i4++;
            i5 = i7;
        }
        if (i5 != length) {
            arrayList.add(new C0985e(tVar, i5, length));
        }
        if (arrayList.isEmpty()) {
            arrayList.add(new C0985e(tVar, 0, 0));
        }
        ArrayList arrayList2 = new ArrayList(arrayList.size());
        int size2 = arrayList.size();
        int i8 = 0;
        while (i8 < size2) {
            C0985e c0985e2 = (C0985e) arrayList.get(i8);
            int i9 = c0985e2.b;
            int i10 = c0985e2.c;
            if (i9 != i10) {
                strSubstring = c0995g2.a.substring(i9, i10);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
            } else {
                strSubstring = "";
            }
            C0995g c0995g4 = new C0995g(strSubstring, AbstractC0996h.b(c0995g2, i9, i10), null, null);
            t tVar3 = (t) c0985e2.a;
            int i11 = i3;
            L l3 = new L(l2.a, tVar.a(tVar3.b == Integer.MIN_VALUE ? new t(tVar3.a, tVar.b, tVar3.c, tVar3.d, tVar3.e, tVar3.f, tVar3.g, tVar3.h, tVar3.i) : tVar3));
            List listB = c0995g4.b();
            List list3 = (List) this.c;
            ArrayList arrayList3 = new ArrayList(list3.size());
            int size3 = list3.size();
            int i12 = 0;
            while (true) {
                i = c0985e2.b;
                if (i12 >= size3) {
                    break;
                }
                L l4 = l3;
                Object obj = list3.get(i12);
                List list4 = list3;
                C0985e c0985e3 = (C0985e) obj;
                int i13 = size2;
                if (AbstractC0996h.c(i, i10, c0985e3.b, c0985e3.c)) {
                    arrayList3.add(obj);
                }
                i12++;
                list3 = list4;
                l3 = l4;
                size2 = i13;
            }
            L l5 = l3;
            int i14 = size2;
            ArrayList arrayList4 = new ArrayList(arrayList3.size());
            int i15 = 0;
            for (int size4 = arrayList3.size(); i15 < size4; size4 = size4) {
                C0985e c0985e4 = (C0985e) arrayList3.get(i15);
                int i16 = c0985e4.b;
                if (i <= i16 && (i2 = c0985e4.c) <= i10) {
                    arrayList4.add(new C0985e(c0985e4.a, i16 - i, i2 - i));
                    i15++;
                } else {
                    throw new IllegalArgumentException("placeholder can not overlap with paragraph.");
                }
            }
            arrayList2.add(new r(new androidx.compose.ui.text.platform.c(strSubstring, l5, listB, arrayList4, iVar, bVar), i, i10));
            i8++;
            c0995g2 = c0995g;
            l2 = l;
            i3 = i11;
            size2 = i14;
        }
        this.f = arrayList2;
    }

    public e(SharedPreferences sharedPreferences, ScheduledThreadPoolExecutor scheduledThreadPoolExecutor) {
        this.a = 8;
        this.e = new ArrayDeque();
        this.b = sharedPreferences;
        this.c = "topic_operation_queue";
        this.d = ",";
        this.f = scheduledThreadPoolExecutor;
    }

    public e(int i) {
        this.a = i;
        switch (i) {
            case 13:
                this.f = new LinkedHashMap();
                this.c = "GET";
                this.d = new h(3);
                break;
        }
    }
}
