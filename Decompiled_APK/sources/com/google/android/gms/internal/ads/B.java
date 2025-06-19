package com.google.android.gms.internal.ads;

import com.google.android.gms.internal.ads.C2824xF;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final /* synthetic */ class B implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Object d;

    public /* synthetic */ B(int i, int i2, long j, Object obj) {
        this.a = i2;
        this.d = obj;
        this.b = i;
        this.c = j;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                String str = Yo.a;
                WD wd = ((SurfaceHolderCallbackC2091gD) ((Fi) this.d).c).a.r;
                RD rdJ = wd.j((C2093gF) wd.d.e);
                wd.i(rdJ, 1018, new com.airbnb.lottie.parser.l(rdJ, this.b, this.c));
                return;
            default:
                final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.d;
                int i = this.b;
                final long j = this.c;
                synchronized (dVar) {
                    final int i2 = i - 1;
                    final Task taskC = ((com.google.firebase.remoteconfig.internal.e) dVar.c).c(3 - i2);
                    final Task taskB = ((com.google.firebase.remoteconfig.internal.b) dVar.d).b();
                    com.google.android.gms.internal.mlkit_vision_common.S3.k(taskC, taskB).f((ScheduledExecutorService) dVar.f, new com.google.android.gms.tasks.a() { // from class: com.google.firebase.remoteconfig.internal.a
                        @Override // com.google.android.gms.tasks.a
                        public final Object h(Task task) throws JSONException {
                            Boolean boolValueOf;
                            JSONObject jSONObject;
                            com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = dVar;
                            Task task2 = taskC;
                            Task task3 = taskB;
                            long j2 = j;
                            int i3 = i2;
                            dVar2.getClass();
                            if (!task2.l()) {
                                return S3.h(new FirebaseRemoteConfigClientException("Failed to auto-fetch config update.", task2.g()));
                            }
                            if (!task3.l()) {
                                return S3.h(new FirebaseRemoteConfigClientException("Failed to get activated config for auto-fetch", task3.g()));
                            }
                            d dVar3 = (d) task2.h();
                            c cVar = (c) task3.h();
                            c cVar2 = dVar3.b;
                            if (cVar2 != null) {
                                boolValueOf = Boolean.valueOf(cVar2.f >= j2);
                            } else {
                                boolValueOf = Boolean.valueOf(dVar3.a == 1);
                            }
                            if (!boolValueOf.booleanValue()) {
                                dVar2.f(i3, j2);
                                return S3.i(null);
                            }
                            if (dVar3.b == null) {
                                return S3.i(null);
                            }
                            if (cVar == null) {
                                C2824xF c2824xFC = c.c();
                                cVar = new c((JSONObject) c2824xFC.b, (Date) c2824xFC.c, (JSONArray) c2824xFC.d, (JSONObject) c2824xFC.e, c2824xFC.a, (JSONArray) c2824xFC.f);
                            }
                            c cVar3 = dVar3.b;
                            c cVarA = c.a(new JSONObject(cVar3.a.toString()));
                            HashMap mapB = cVar.b();
                            HashMap mapB2 = cVar3.b();
                            HashSet hashSet = new HashSet();
                            JSONObject jSONObject2 = cVar.b;
                            Iterator<String> itKeys = jSONObject2.keys();
                            while (true) {
                                boolean zHasNext = itKeys.hasNext();
                                jSONObject = cVarA.b;
                                if (!zHasNext) {
                                    break;
                                }
                                String next = itKeys.next();
                                JSONObject jSONObject3 = cVar3.b;
                                if (!jSONObject3.has(next)) {
                                    hashSet.add(next);
                                } else if (jSONObject2.get(next).equals(jSONObject3.get(next))) {
                                    JSONObject jSONObject4 = cVar.e;
                                    boolean zHas = jSONObject4.has(next);
                                    JSONObject jSONObject5 = cVar3.e;
                                    if ((zHas && !jSONObject5.has(next)) || (!jSONObject4.has(next) && jSONObject5.has(next))) {
                                        hashSet.add(next);
                                    } else if (jSONObject4.has(next) && jSONObject5.has(next) && !jSONObject4.getJSONObject(next).toString().equals(jSONObject5.getJSONObject(next).toString())) {
                                        hashSet.add(next);
                                    } else if (mapB.containsKey(next) != mapB2.containsKey(next)) {
                                        hashSet.add(next);
                                    } else if (mapB.containsKey(next) && mapB2.containsKey(next) && !((Map) mapB.get(next)).equals(mapB2.get(next))) {
                                        hashSet.add(next);
                                    } else {
                                        jSONObject.remove(next);
                                    }
                                } else {
                                    hashSet.add(next);
                                }
                            }
                            Iterator<String> itKeys2 = jSONObject.keys();
                            while (itKeys2.hasNext()) {
                                hashSet.add(itKeys2.next());
                            }
                            if (hashSet.isEmpty()) {
                                return S3.i(null);
                            }
                            synchronized (dVar2) {
                                Iterator it2 = ((LinkedHashSet) dVar2.a).iterator();
                                while (it2.hasNext()) {
                                    ((g) it2.next()).getClass();
                                }
                            }
                            return S3.i(null);
                        }
                    });
                }
                return;
        }
    }
}
