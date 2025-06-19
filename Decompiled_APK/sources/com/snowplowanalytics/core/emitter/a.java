package com.snowplowanalytics.core.emitter;

import android.app.Activity;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.net.Uri;
import androidx.compose.animation.d0;
import androidx.transition.C1412o;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.mlkit_vision_barcode.E6;
import com.snowplowanalytics.snowplow.network.e;
import com.snowplowanalytics.snowplow.network.f;
import com.snowplowanalytics.snowplow.network.g;
import com.snowplowanalytics.snowplow.network.h;
import com.snowplowanalytics.snowplow.network.i;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.B;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.x;
import okhttp3.A;
import okhttp3.C;
import okhttp3.E;
import okhttp3.n;

/* loaded from: classes3.dex */
public final class a {
    public final AtomicReference A;
    public final AtomicReference B;
    public Map C;
    public long D;
    public long E;
    public final String a;
    public final boolean b;
    public final AtomicBoolean c;
    public final AtomicBoolean d;
    public final boolean e;
    public final Activity f;
    public final String g;
    public int h;
    public final TimeUnit i;
    public n j;
    public int k;
    public A l;
    public final androidx.work.impl.background.greedy.d m;
    public final EnumSet n;
    public final int o;
    public final int p;
    public int q;
    public long r;
    public long s;
    public com.snowplowanalytics.snowplow.network.c t;
    public com.snowplowanalytics.snowplow.emitter.a u;
    public g v;
    public Integer w;
    public String x;
    public final AtomicReference y;
    public boolean z;

    public a(androidx.work.impl.background.greedy.d dVar, Activity context, String collectorUri, androidx.credentials.playservices.controllers.BeginSignIn.c cVar) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        f fVar;
        Intrinsics.checkNotNullParameter("appTracker", "namespace");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(collectorUri, "collectorUri");
        String TAG = a.class.getSimpleName();
        this.a = TAG;
        this.c = new AtomicBoolean(false);
        this.d = new AtomicBoolean(false);
        this.i = b.j;
        this.k = b.h;
        if (dVar == null) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter("appTracker", "namespace");
            dVar = new androidx.work.impl.background.greedy.d();
            dVar.b = new ArrayList();
            dVar.e = new String[]{"id", "eventData", "dateCreated"};
            dVar.a = -1L;
            c.b(new androidx.work.impl.A(13, dVar, context));
        }
        this.m = dVar;
        EnumSet enumSet = b.a;
        this.n = enumSet;
        this.o = b.c;
        this.p = b.d;
        this.q = b.b;
        this.r = b.e;
        this.s = b.f;
        this.t = com.snowplowanalytics.snowplow.network.c.b;
        this.u = com.snowplowanalytics.snowplow.emitter.a.Single;
        g gVar = g.b;
        this.v = gVar;
        this.w = Integer.valueOf(b.g);
        AtomicReference atomicReference = new AtomicReference();
        this.y = atomicReference;
        this.z = false;
        this.A = new AtomicReference();
        this.B = new AtomicReference(Boolean.valueOf(b.i));
        this.D = b.l;
        this.E = b.k;
        this.f = context;
        cVar.invoke(this);
        if (((com.snowplowanalytics.snowplow.network.d) atomicReference.get()) == null) {
            this.e = false;
            if (!D.r(collectorUri, "http", false)) {
                collectorUri = (this.v == gVar ? DtbConstants.HTTPS : "http://").concat(collectorUri);
            }
            this.g = collectorUri;
            Integer num = this.w;
            if (num != null) {
                int iIntValue = num.intValue();
                e eVar = new e(collectorUri, context);
                eVar.a(this.t);
                eVar.b(enumSet);
                eVar.e = iIntValue;
                eVar.h = this.x;
                eVar.f = this.l;
                eVar.g = this.j;
                eVar.i = this.z;
                eVar.j = this.C;
                fVar = new f(eVar);
            } else {
                fVar = null;
            }
            d(fVar);
        } else {
            this.e = true;
        }
        int i = this.k;
        if (i > 2) {
            if (i >= 2) {
                c.b = i;
            } else {
                ScheduledExecutorService scheduledExecutorService = c.a;
            }
        }
        this.b = true;
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.e(TAG, "Emitter created successfully!", new Object[0]);
    }

    public final void a(com.snowplowanalytics.snowplow.network.d dVar) throws Throwable {
        long size;
        Object obj;
        List list;
        SQLiteDatabase sQLiteDatabase;
        Cursor cursor;
        Cursor cursorQuery;
        HashMap map;
        Activity activity;
        String str;
        AtomicBoolean atomicBoolean;
        String str2;
        Iterator it2;
        String str3;
        String str4;
        Uri.Builder builder;
        int iDelete;
        SQLiteDatabase sQLiteDatabase2;
        boolean zBooleanValue;
        Integer num;
        com.snowplowanalytics.snowplow.network.c cVar;
        com.snowplowanalytics.snowplow.network.c cVar2;
        C cI;
        a aVar = this;
        boolean z = aVar.d.get();
        AtomicBoolean atomicBoolean2 = aVar.c;
        String TAG = aVar.a;
        int i = 0;
        if (z) {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            com.snowplowanalytics.core.tracker.e.a(TAG, "Emitter paused.", new Object[0]);
            atomicBoolean2.compareAndSet(true, false);
            return;
        }
        Activity activity2 = aVar.f;
        if (!E6.d(activity2)) {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            com.snowplowanalytics.core.tracker.e.a(TAG, "Emitter loop stopping: emitter offline.", new Object[0]);
            atomicBoolean2.compareAndSet(true, false);
            return;
        }
        if (dVar == null) {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            com.snowplowanalytics.core.tracker.e.a(TAG, "No networkConnection set.", new Object[0]);
            atomicBoolean2.compareAndSet(true, false);
            return;
        }
        androidx.work.impl.background.greedy.d dVar2 = aVar.m;
        String str5 = "events";
        if (dVar2.b()) {
            dVar2.h();
            size = DatabaseUtils.queryNumEntries((SQLiteDatabase) dVar2.c, "events");
        } else {
            size = ((ArrayList) dVar2.b).size();
        }
        if (size <= 0) {
            int i2 = aVar.h;
            if (i2 >= aVar.p) {
                Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                com.snowplowanalytics.core.tracker.e.a(TAG, "Emitter loop stopping: empty limit reached.", new Object[0]);
                atomicBoolean2.compareAndSet(true, false);
                return;
            }
            aVar.h = i2 + 1;
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            com.snowplowanalytics.core.tracker.e.b(TAG, "Emitter database empty: " + aVar.h, new Object[0]);
            try {
                aVar.i.sleep(aVar.o);
            } catch (InterruptedException e) {
                Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                com.snowplowanalytics.core.tracker.e.b(TAG, "Emitter thread sleep interrupted: " + e, new Object[0]);
            }
            a(dVar);
            return;
        }
        aVar.h = 0;
        int i3 = aVar.q;
        String str6 = "d";
        if (dVar2.b()) {
            dVar2.h();
            ArrayList arrayList = new ArrayList();
            String strF = android.support.v4.media.session.a.f(i3, "id DESC LIMIT ");
            ArrayList arrayList2 = new ArrayList();
            if (!dVar2.b() || (sQLiteDatabase = (SQLiteDatabase) dVar2.c) == null) {
                obj = "eventData";
            } else {
                try {
                    obj = "eventData";
                    cursorQuery = sQLiteDatabase.query("events", (String[]) dVar2.e, null, null, null, null, strF);
                } catch (Throwable th) {
                    th = th;
                    cursor = null;
                }
                try {
                    cursorQuery.moveToFirst();
                    while (!cursorQuery.isAfterLast()) {
                        HashMap map2 = new HashMap();
                        map2.put("id", Long.valueOf(cursorQuery.getLong(i)));
                        byte[] bytes = cursorQuery.getBlob(1);
                        Intrinsics.checkNotNullExpressionValue(bytes, "cursor.getBlob(1)");
                        Intrinsics.checkNotNullParameter(bytes, "bytes");
                        try {
                            try {
                                ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
                                ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
                                Object object = objectInputStream.readObject();
                                map = object instanceof HashMap ? (HashMap) object : null;
                                objectInputStream.close();
                                byteArrayInputStream.close();
                            } catch (IOException e2) {
                                e2.printStackTrace();
                                map = null;
                                map2.put(obj, map);
                                map2.put("dateCreated", cursorQuery.getString(2));
                                cursorQuery.moveToNext();
                                arrayList2.add(map2);
                                i = 0;
                            }
                        } catch (ClassNotFoundException e3) {
                            e3.printStackTrace();
                            map = null;
                            map2.put(obj, map);
                            map2.put("dateCreated", cursorQuery.getString(2));
                            cursorQuery.moveToNext();
                            arrayList2.add(map2);
                            i = 0;
                        } catch (NullPointerException e4) {
                            e4.printStackTrace();
                            map = null;
                            map2.put(obj, map);
                            map2.put("dateCreated", cursorQuery.getString(2));
                            cursorQuery.moveToNext();
                            arrayList2.add(map2);
                            i = 0;
                        }
                        map2.put(obj, map);
                        map2.put("dateCreated", cursorQuery.getString(2));
                        cursorQuery.moveToNext();
                        arrayList2.add(map2);
                        i = 0;
                    }
                    cursorQuery.close();
                } catch (Throwable th2) {
                    th = th2;
                    cursor = cursorQuery;
                    if (cursor != null) {
                        cursor.close();
                    }
                    throw th;
                }
            }
            Iterator it3 = arrayList2.iterator();
            while (it3.hasNext()) {
                Map map3 = (Map) it3.next();
                com.snowplowanalytics.snowplow.payload.b bVar = new com.snowplowanalytics.snowplow.payload.b();
                Object obj2 = map3.get(obj);
                Map map4 = obj2 instanceof Map ? (Map) obj2 : null;
                if (map4 != null) {
                    bVar.c(map4);
                }
                Object obj3 = map3.get("id");
                Long l = obj3 instanceof Long ? (Long) obj3 : null;
                if (l == null) {
                    Intrinsics.checkNotNullExpressionValue("d", "TAG");
                    com.snowplowanalytics.core.tracker.e.b("d", "Unable to get ID of an event extracted from the database.", new Object[0]);
                } else {
                    arrayList.add(new com.snowplowanalytics.snowplow.emitter.b(bVar, l.longValue()));
                    atomicBoolean2 = atomicBoolean2;
                    obj = obj;
                }
            }
            list = arrayList;
        } else {
            list = K.a;
        }
        AtomicBoolean atomicBoolean3 = atomicBoolean2;
        f fVar = (f) dVar;
        ArrayList requests = new ArrayList();
        String strValueOf = String.valueOf(System.currentTimeMillis());
        com.snowplowanalytics.snowplow.network.c cVar3 = com.snowplowanalytics.snowplow.network.c.a;
        String str7 = "stm";
        com.snowplowanalytics.snowplow.network.c cVar4 = fVar.c;
        if (cVar4 == cVar3) {
            Iterator it4 = list.iterator();
            while (it4.hasNext()) {
                com.snowplowanalytics.snowplow.emitter.b bVar2 = (com.snowplowanalytics.snowplow.emitter.b) it4.next();
                Iterator it5 = it4;
                com.snowplowanalytics.snowplow.payload.b bVar3 = bVar2 != null ? bVar2.a : null;
                if (bVar3 != null) {
                    bVar3.a("stm", strValueOf);
                    requests.add(new h(bVar3, bVar2.b, aVar.b(bVar3, new ArrayList(), cVar4)));
                    it4 = it5;
                    activity2 = activity2;
                    atomicBoolean3 = atomicBoolean3;
                    str6 = str6;
                } else {
                    it4 = it5;
                }
            }
            activity = activity2;
            str = str6;
            atomicBoolean = atomicBoolean3;
            str2 = "events";
        } else {
            activity = activity2;
            str = "d";
            atomicBoolean = atomicBoolean3;
            ArrayList arrayList3 = new ArrayList();
            ArrayList arrayList4 = new ArrayList();
            Iterator it6 = list.iterator();
            while (it6.hasNext()) {
                com.snowplowanalytics.snowplow.emitter.b bVar4 = (com.snowplowanalytics.snowplow.emitter.b) it6.next();
                if (bVar4 != null) {
                    com.snowplowanalytics.snowplow.payload.b bVar5 = bVar4.a;
                    bVar5.a(str7, strValueOf);
                    it2 = it6;
                    boolean zB = aVar.b(bVar5, new ArrayList(), cVar4);
                    str3 = str5;
                    str4 = str7;
                    long j = bVar4.b;
                    if (zB) {
                        requests.add(new h(bVar5, j, true));
                    } else if (aVar.b(bVar5, arrayList4, cVar4)) {
                        requests.add(new h(arrayList4, arrayList3));
                        arrayList4 = new ArrayList();
                        arrayList3 = new ArrayList();
                        arrayList4.add(bVar5);
                        arrayList3.add(Long.valueOf(j));
                    } else {
                        arrayList4.add(bVar5);
                        arrayList3.add(Long.valueOf(j));
                    }
                } else {
                    it2 = it6;
                    str3 = str5;
                    str4 = str7;
                }
                it6 = it2;
                str5 = str3;
                str7 = str4;
            }
            str2 = str5;
            if (!arrayList4.isEmpty()) {
                requests.add(new h(arrayList4, arrayList3));
            }
        }
        Intrinsics.checkNotNullParameter(requests, "requests");
        ArrayList arrayList5 = new ArrayList();
        ArrayList arrayList6 = new ArrayList();
        Iterator it7 = requests.iterator();
        while (true) {
            boolean zHasNext = it7.hasNext();
            builder = fVar.h;
            if (!zHasNext) {
                break;
            }
            h hVar = (h) it7.next();
            String str8 = hVar.d;
            if (str8 == null) {
                str8 = f.i;
            }
            Map map5 = fVar.f;
            Iterator it8 = it7;
            androidx.work.impl.background.greedy.d dVar3 = dVar2;
            com.snowplowanalytics.snowplow.payload.b bVar6 = hVar.a;
            if (cVar4 == cVar3) {
                builder.clearQuery();
                HashMap map6 = bVar6.b;
                for (String str9 : map6.keySet()) {
                    com.snowplowanalytics.snowplow.network.c cVar5 = cVar3;
                    com.snowplowanalytics.snowplow.network.c cVar6 = cVar4;
                    Object obj4 = map6.get(str9);
                    HashMap map7 = map6;
                    builder.appendQueryParameter(str9, obj4 instanceof String ? (String) obj4 : null);
                    cVar4 = cVar6;
                    cVar3 = cVar5;
                    map6 = map7;
                }
                cVar = cVar3;
                cVar2 = cVar4;
                String string = builder.build().toString();
                Intrinsics.checkNotNullExpressionValue(string, "uriBuilder.build().toString()");
                com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
                eVar.r(string);
                eVar.l("User-Agent", str8);
                eVar.n("GET", null);
                if (fVar.e) {
                    eVar.l("SP-Anonymous", "*");
                }
                if (map5 != null) {
                    for (Map.Entry entry : map5.entrySet()) {
                        eVar.l((String) entry.getKey(), (String) entry.getValue());
                    }
                }
                cI = eVar.i();
            } else {
                cVar = cVar3;
                cVar2 = cVar4;
                String string2 = builder.build().toString();
                Intrinsics.checkNotNullExpressionValue(string2, "uriBuilder.build().toString()");
                E body = C1412o.f(bVar6.toString(), fVar.b);
                com.quizlet.remote.model.notes.e eVar2 = new com.quizlet.remote.model.notes.e(13);
                eVar2.r(string2);
                eVar2.l("User-Agent", str8);
                Intrinsics.checkNotNullParameter(body, "body");
                eVar2.n("POST", body);
                if (fVar.e) {
                    eVar2.l("SP-Anonymous", "*");
                }
                if (map5 != null) {
                    for (Map.Entry entry2 : map5.entrySet()) {
                        eVar2.l((String) entry2.getKey(), (String) entry2.getValue());
                    }
                }
                cI = eVar2.i();
            }
            Future futureB = c.b(new androidx.work.impl.A(14, fVar, cI));
            if (futureB != null) {
                arrayList5.add(futureB);
            }
            it7 = it8;
            dVar2 = dVar3;
            cVar4 = cVar2;
            cVar3 = cVar;
        }
        androidx.work.impl.background.greedy.d dVar4 = dVar2;
        String TAG2 = fVar.a;
        Intrinsics.checkNotNullExpressionValue(TAG2, "TAG");
        com.snowplowanalytics.core.tracker.e.a(TAG2, "Request Futures: %s", Integer.valueOf(arrayList5.size()));
        int size2 = arrayList5.size();
        for (int i4 = 0; i4 < size2; i4++) {
            try {
                Object obj5 = ((Future) arrayList5.get(i4)).get(fVar.d, TimeUnit.SECONDS);
                num = obj5 instanceof Integer ? (Integer) obj5 : null;
            } catch (InterruptedException e5) {
                Intrinsics.checkNotNullExpressionValue(TAG2, "TAG");
                com.snowplowanalytics.core.tracker.e.b(TAG2, "Request Future was interrupted: %s", e5.getMessage());
            } catch (ExecutionException e6) {
                Intrinsics.checkNotNullExpressionValue(TAG2, "TAG");
                com.snowplowanalytics.core.tracker.e.b(TAG2, "Request Future failed: %s", e6.getMessage());
            } catch (TimeoutException e7) {
                Intrinsics.checkNotNullExpressionValue(TAG2, "TAG");
                com.snowplowanalytics.core.tracker.e.b(TAG2, "Request Future had a timeout: %s", e7.getMessage());
            }
            int iIntValue = num != null ? num.intValue() : -1;
            h hVar2 = (h) requests.get(i4);
            ArrayList arrayList7 = hVar2.b;
            boolean z2 = hVar2.c;
            arrayList6.add(new i(iIntValue, arrayList7, z2));
            if (z2) {
                Intrinsics.checkNotNullExpressionValue(TAG2, "TAG");
                com.snowplowanalytics.core.tracker.e.d(TAG2, "Request is oversized for emitter event IDs: %s", arrayList7.toString());
            }
        }
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.e(TAG, "Processing emitter results.", new Object[0]);
        ArrayList list2 = new ArrayList();
        Iterator it9 = arrayList6.iterator();
        int size3 = 0;
        int size4 = 0;
        int size5 = 0;
        while (it9.hasNext()) {
            i iVar = (i) it9.next();
            int i5 = iVar.a;
            boolean z3 = 200 <= i5 && i5 < 300;
            ArrayList arrayList8 = iVar.c;
            if (z3) {
                list2.addAll(arrayList8);
                size4 += arrayList8.size();
            } else {
                Map map8 = (Map) aVar.A.get();
                Object obj6 = aVar.B.get();
                Intrinsics.checkNotNullExpressionValue(obj6, "_retryFailedRequests.get()");
                boolean zBooleanValue2 = ((Boolean) obj6).booleanValue();
                int i6 = iVar.a;
                if ((200 <= i6 && i6 < 300) || !zBooleanValue2 || iVar.b) {
                    zBooleanValue = false;
                } else if (map8 == null || !map8.containsKey(Integer.valueOf(i6))) {
                    zBooleanValue = !new HashSet(B.j(400, 401, 403, 410, 422)).contains(Integer.valueOf(i6));
                } else {
                    Object obj7 = map8.get(Integer.valueOf(i6));
                    Intrinsics.d(obj7);
                    zBooleanValue = ((Boolean) obj7).booleanValue();
                }
                if (zBooleanValue) {
                    size5 += arrayList8.size();
                    Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                    com.snowplowanalytics.core.tracker.e.b(TAG, "Request sending failed but we will retry later.", new Object[0]);
                } else {
                    size3 += arrayList8.size();
                    list2.addAll(arrayList8);
                    Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                    com.snowplowanalytics.core.tracker.e.b(TAG, d0.s(new Object[]{Integer.valueOf(i6)}, 1, "Sending events to Collector failed with status %d. Events will be dropped.", "format(format, *args)"), new Object[0]);
                }
                aVar = this;
            }
        }
        dVar4.getClass();
        Intrinsics.checkNotNullParameter(list2, "ids");
        if (!list2.isEmpty()) {
            if (!dVar4.b() || (sQLiteDatabase2 = (SQLiteDatabase) dVar4.c) == null) {
                iDelete = -1;
            } else {
                StringBuilder sb = new StringBuilder("id in (");
                Intrinsics.checkNotNullParameter(list2, "list");
                StringBuilder sb2 = new StringBuilder();
                int size6 = list2.size();
                for (int i7 = 0; i7 < size6; i7++) {
                    if (((Long) list2.get(i7)) != null) {
                        sb2.append(list2.get(i7));
                        if (i7 < list2.size() - 1) {
                            sb2.append(",");
                        }
                    }
                }
                String string3 = sb2.toString();
                Intrinsics.checkNotNullExpressionValue(string3, "s.toString()");
                if (D.k(string3, ",", false)) {
                    sb2 = new StringBuilder(sb2.substring(0, sb2.length() - 1));
                }
                String string4 = sb2.toString();
                Intrinsics.checkNotNullExpressionValue(string4, "s.toString()");
                sb.append(string4);
                sb.append(')');
                iDelete = sQLiteDatabase2.delete(str2, sb.toString(), null);
            }
            String TAG3 = str;
            Intrinsics.checkNotNullExpressionValue(TAG3, "TAG");
            com.snowplowanalytics.core.tracker.e.a(TAG3, "Removed events from database: %s", Integer.valueOf(iDelete));
            list2.size();
        }
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.a(TAG, "Success Count: %s", Integer.valueOf(size4));
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.a(TAG, "Failure Count: %s", Integer.valueOf(size3 + size5));
        if (size5 <= 0 || size4 != 0) {
            a(dVar);
            return;
        }
        if (E6.d(activity)) {
            Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
            Uri uriBuild = builder.clearQuery().build();
            Intrinsics.checkNotNullExpressionValue(uriBuild, "uriBuilder.clearQuery().build()");
            com.snowplowanalytics.core.tracker.e.b(TAG, "Ensure collector path is valid: %s", uriBuild);
        }
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.b(TAG, "Emitter loop stopping: failures.", new Object[0]);
        atomicBoolean.compareAndSet(true, false);
    }

    public final boolean b(com.snowplowanalytics.snowplow.payload.b bVar, ArrayList arrayList, com.snowplowanalytics.snowplow.network.c cVar) {
        long j = cVar == com.snowplowanalytics.snowplow.network.c.a ? this.r : this.s;
        long jD = bVar.d();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            jD += ((com.snowplowanalytics.snowplow.payload.b) it2.next()).d();
        }
        return jD + ((long) (!arrayList.isEmpty() ? arrayList.size() + 88 : 0)) > j;
    }

    public final void c() throws SQLException {
        long j = this.D;
        long j2 = this.E;
        androidx.work.impl.background.greedy.d dVar = this.m;
        if (dVar.b()) {
            dVar.h();
            SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) dVar.c;
            if (sQLiteDatabase != null) {
                StringBuilder sb = new StringBuilder("\n                DELETE FROM events\n                WHERE id NOT IN (\n                    SELECT id\n                    FROM events\n                    WHERE dateCreated >= datetime('now','-");
                kotlin.time.a aVar = kotlin.time.b.b;
                sb.append(kotlin.time.b.i(j2, kotlin.time.d.d));
                sb.append(" seconds')\n                    ORDER BY dateCreated DESC, id DESC\n                    LIMIT ");
                sb.append(j);
                sb.append("\n                )\n                ");
                sQLiteDatabase.execSQL(x.c(sb.toString()));
            }
        }
    }

    public final void d(com.snowplowanalytics.snowplow.network.d dVar) {
        this.y.set(dVar);
    }

    public final void e() {
        String TAG = this.a;
        Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
        com.snowplowanalytics.core.tracker.e.a(TAG, "Shutting down emitter.", new Object[0]);
        this.c.compareAndSet(true, false);
        ScheduledExecutorService scheduledExecutorService = c.a;
        if (scheduledExecutorService != null) {
            try {
                scheduledExecutorService.shutdown();
            } catch (Exception e) {
                String message = e.getMessage();
                if (message == null) {
                    message = "Failed to shutdown";
                }
                com.snowplowanalytics.core.tracker.e.b("Executor", message, new Object[0]);
            }
            c.a = null;
        }
    }
}
