package androidx.camera.camera2.internal;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.util.Size;
import androidx.activity.RunnableC0041m;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.camera.core.C0187j;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.view.PreviewView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.work.EnumC1440n;
import com.android.billingclient.api.Purchase;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.braze.ui.inappmessage.IInAppMessageViewWrapper;
import com.braze.ui.inappmessage.listeners.IWebViewClientStateListener;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_common.R2;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.google.android.gms.tasks.Task;
import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigClientException;
import com.google.firebase.remoteconfig.FirebaseRemoteConfigException;
import com.onetrust.otpublishers.headless.Public.OTNetworkRequestCallback;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import io.reactivex.rxjava3.internal.operators.observable.C4905y;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class T implements androidx.camera.core.impl.utils.futures.a, androidx.concurrent.futures.j, androidx.camera.core.i0, IWebViewClientStateListener, com.google.android.datatransport.runtime.synchronization.a, com.google.android.datatransport.runtime.scheduling.persistence.e, com.google.android.gms.tasks.a, com.google.android.gms.tasks.e, com.google.android.gms.tasks.d, OTNetworkRequestCallback, io.reactivex.rxjava3.functions.h, io.reactivex.rxjava3.core.r, io.reactivex.rxjava3.core.j, com.quizlet.uicommon.ui.common.dialogs.f, io.reactivex.rxjava3.core.c, androidx.fragment.app.m0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ T(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        com.google.android.datatransport.runtime.scheduling.a aVar = (com.google.android.datatransport.runtime.scheduling.a) this.b;
        com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) aVar.d;
        gVar.getClass();
        com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) this.c;
        com.google.android.datatransport.runtime.h hVar = (com.google.android.datatransport.runtime.h) this.d;
        if (Log.isLoggable("TRuntime.".concat("SQLiteEventStore"), 3)) {
            new StringBuilder("Storing event with priority=").append(iVar.c);
        }
        ((Long) gVar.f(new T(gVar, hVar, iVar, 9))).getClass();
        aVar.a.a(iVar, 1, false);
        return null;
    }

    @Override // com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) throws Throwable {
        long jInsert;
        Cursor cursor;
        int i;
        com.google.android.datatransport.runtime.firebase.transport.c cVar;
        com.google.android.datatransport.runtime.firebase.transport.c cVar2;
        int i2 = 5;
        int i3 = 4;
        int i4 = 3;
        com.google.android.datatransport.runtime.firebase.transport.c cVar3 = com.google.android.datatransport.runtime.firebase.transport.c.CACHE_FULL;
        int i5 = 2;
        int i6 = 0;
        Object obj2 = this.d;
        Object obj3 = this.c;
        Object obj4 = this.b;
        int i7 = 1;
        switch (this.a) {
            case 9:
                SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) obj4;
                long jSimpleQueryForLong = gVar.a().compileStatement("PRAGMA page_size").simpleQueryForLong() * gVar.a().compileStatement("PRAGMA page_count").simpleQueryForLong();
                com.google.android.datatransport.runtime.scheduling.persistence.a aVar = gVar.d;
                long j = aVar.a;
                com.google.android.datatransport.runtime.h hVar = (com.google.android.datatransport.runtime.h) obj3;
                String str = hVar.a;
                if (jSimpleQueryForLong >= j) {
                    gVar.j(1L, cVar3, str);
                    return -1L;
                }
                com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) obj2;
                Long lD = com.google.android.datatransport.runtime.scheduling.persistence.g.d(sQLiteDatabase, iVar);
                if (lD != null) {
                    jInsert = lD.longValue();
                } else {
                    ContentValues contentValues = new ContentValues();
                    contentValues.put("backend_name", iVar.a);
                    contentValues.put("priority", Integer.valueOf(com.google.android.datatransport.runtime.util.a.a(iVar.c)));
                    contentValues.put("next_request_ms", (Integer) 0);
                    byte[] bArr = iVar.b;
                    if (bArr != null) {
                        contentValues.put("extras", Base64.encodeToString(bArr, 0));
                    }
                    jInsert = sQLiteDatabase.insert("transport_contexts", null, contentValues);
                }
                com.google.android.datatransport.runtime.k kVar = hVar.c;
                byte[] bArr2 = kVar.b;
                int length = bArr2.length;
                int i8 = aVar.e;
                boolean z = length <= i8;
                ContentValues contentValues2 = new ContentValues();
                contentValues2.put("context_id", Long.valueOf(jInsert));
                contentValues2.put("transport_name", str);
                contentValues2.put("timestamp_ms", Long.valueOf(hVar.d));
                contentValues2.put("uptime_ms", Long.valueOf(hVar.e));
                contentValues2.put("payload_encoding", kVar.a.a);
                contentValues2.put("code", hVar.b);
                contentValues2.put("num_attempts", (Integer) 0);
                contentValues2.put("inline", Boolean.valueOf(z));
                contentValues2.put("payload", z ? bArr2 : new byte[0]);
                contentValues2.put("product_id", hVar.g);
                contentValues2.put("pseudonymous_id", hVar.h);
                contentValues2.put("experiment_ids_clear_blob", hVar.i);
                contentValues2.put("experiment_ids_encrypted_blob", hVar.j);
                long jInsert2 = sQLiteDatabase.insert("events", null, contentValues2);
                if (!z) {
                    int iCeil = (int) Math.ceil(bArr2.length / i8);
                    for (int i9 = 1; i9 <= iCeil; i9++) {
                        byte[] bArrCopyOfRange = Arrays.copyOfRange(bArr2, (i9 - 1) * i8, Math.min(i9 * i8, bArr2.length));
                        ContentValues contentValues3 = new ContentValues();
                        contentValues3.put("event_id", Long.valueOf(jInsert2));
                        contentValues3.put("sequence_num", Integer.valueOf(i9));
                        contentValues3.put("bytes", bArrCopyOfRange);
                        sQLiteDatabase.insert("event_payloads", null, contentValues3);
                    }
                }
                for (Map.Entry entry : Collections.unmodifiableMap(hVar.f).entrySet()) {
                    ContentValues contentValues4 = new ContentValues();
                    contentValues4.put("event_id", Long.valueOf(jInsert2));
                    contentValues4.put("name", (String) entry.getKey());
                    contentValues4.put("value", (String) entry.getValue());
                    sQLiteDatabase.insert("event_metadata", null, contentValues4);
                }
                return Long.valueOf(jInsert2);
            case 10:
                Cursor cursor2 = (Cursor) obj;
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar2 = (com.google.android.datatransport.runtime.scheduling.persistence.g) obj4;
                gVar2.getClass();
                while (cursor2.moveToNext()) {
                    long j2 = cursor2.getLong(0);
                    int i10 = cursor2.getInt(7) != 0 ? i7 : 0;
                    androidx.compose.runtime.internal.j jVar = new androidx.compose.runtime.internal.j();
                    jVar.f = new HashMap();
                    String string = cursor2.getString(i7);
                    if (string == null) {
                        throw new NullPointerException("Null transportName");
                    }
                    jVar.a = string;
                    jVar.d = Long.valueOf(cursor2.getLong(i5));
                    jVar.e = Long.valueOf(cursor2.getLong(3));
                    if (i10 != 0) {
                        String string2 = cursor2.getString(4);
                        jVar.c = new com.google.android.datatransport.runtime.k(string2 == null ? com.google.android.datatransport.runtime.scheduling.persistence.g.f : new com.google.android.datatransport.c(string2), cursor2.getBlob(5));
                        i = i7;
                    } else {
                        String string3 = cursor2.getString(4);
                        com.google.android.datatransport.c cVar4 = string3 == null ? com.google.android.datatransport.runtime.scheduling.persistence.g.f : new com.google.android.datatransport.c(string3);
                        Cursor cursorQuery = gVar2.a().query("event_payloads", new String[]{"bytes"}, "event_id = ?", new String[]{String.valueOf(j2)}, null, null, "sequence_num");
                        try {
                            ArrayList arrayList = new ArrayList();
                            int length2 = 0;
                            while (cursorQuery.moveToNext()) {
                                int i11 = i7;
                                byte[] blob = cursorQuery.getBlob(0);
                                arrayList.add(blob);
                                length2 += blob.length;
                                i7 = i11;
                            }
                            i = i7;
                            byte[] bArr3 = new byte[length2];
                            int i12 = 0;
                            int length3 = 0;
                            while (i12 < arrayList.size()) {
                                byte[] bArr4 = (byte[]) arrayList.get(i12);
                                cursor = cursorQuery;
                                try {
                                    ArrayList arrayList2 = arrayList;
                                    System.arraycopy(bArr4, 0, bArr3, length3, bArr4.length);
                                    length3 += bArr4.length;
                                    i12++;
                                    cursorQuery = cursor;
                                    arrayList = arrayList2;
                                } catch (Throwable th) {
                                    th = th;
                                    cursor.close();
                                    throw th;
                                }
                            }
                            cursorQuery.close();
                            jVar.c = new com.google.android.datatransport.runtime.k(cVar4, bArr3);
                        } catch (Throwable th2) {
                            th = th2;
                            cursor = cursorQuery;
                        }
                    }
                    if (!cursor2.isNull(6)) {
                        jVar.b = Integer.valueOf(cursor2.getInt(6));
                    }
                    if (!cursor2.isNull(8)) {
                        jVar.g = Integer.valueOf(cursor2.getInt(8));
                    }
                    if (!cursor2.isNull(9)) {
                        jVar.h = cursor2.getString(9);
                    }
                    if (!cursor2.isNull(10)) {
                        jVar.i = cursor2.getBlob(10);
                    }
                    if (!cursor2.isNull(11)) {
                        jVar.j = cursor2.getBlob(11);
                    }
                    ((ArrayList) obj3).add(new com.google.android.datatransport.runtime.scheduling.persistence.b(j2, (com.google.android.datatransport.runtime.i) obj2, jVar.b()));
                    i7 = i;
                    i5 = 2;
                }
                return null;
            case 11:
                Cursor cursor3 = (Cursor) obj;
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar3 = (com.google.android.datatransport.runtime.scheduling.persistence.g) obj4;
                gVar3.getClass();
                while (true) {
                    HashMap map = (HashMap) obj3;
                    if (cursor3.moveToNext()) {
                        String string4 = cursor3.getString(i6);
                        int i13 = cursor3.getInt(1);
                        com.google.android.datatransport.runtime.firebase.transport.c cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.REASON_UNKNOWN;
                        if (i13 != 0) {
                            if (i13 == 1) {
                                cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.MESSAGE_TOO_OLD;
                            } else if (i13 == 2) {
                                cVar = cVar3;
                                cVar2 = cVar;
                            } else if (i13 == i4) {
                                cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.PAYLOAD_TOO_BIG;
                            } else if (i13 == i3) {
                                cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.MAX_RETRIES_REACHED;
                            } else if (i13 == i2) {
                                cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.INVALID_PAYLOD;
                            } else if (i13 == 6) {
                                cVar5 = com.google.android.datatransport.runtime.firebase.transport.c.SERVER_ERROR;
                            } else {
                                R2.c("SQLiteEventStore", "%n is not valid. No matched LogEventDropped-Reason found. Treated it as REASON_UNKNOWN", Integer.valueOf(i13));
                            }
                            cVar2 = cVar3;
                            cVar = cVar5;
                        } else {
                            cVar2 = cVar3;
                            cVar = cVar5;
                        }
                        long j3 = cursor3.getLong(2);
                        if (!map.containsKey(string4)) {
                            map.put(string4, new ArrayList());
                        }
                        ((List) map.get(string4)).add(new com.google.android.datatransport.runtime.firebase.transport.d(j3, cVar));
                        cVar3 = cVar2;
                        i2 = 5;
                        i3 = 4;
                        i4 = 3;
                        i6 = 0;
                    } else {
                        Iterator it2 = map.entrySet().iterator();
                        while (true) {
                            com.quizlet.data.repository.achievements.h hVar2 = (com.quizlet.data.repository.achievements.h) obj2;
                            if (!it2.hasNext()) {
                                long jE = gVar3.b.e();
                                SQLiteDatabase sQLiteDatabaseA = gVar3.a();
                                sQLiteDatabaseA.beginTransaction();
                                try {
                                    Cursor cursorRawQuery = sQLiteDatabaseA.rawQuery("SELECT last_metrics_upload_ms FROM global_log_event_state LIMIT 1", new String[0]);
                                    try {
                                        cursorRawQuery.moveToNext();
                                        com.google.android.datatransport.runtime.firebase.transport.g gVar4 = new com.google.android.datatransport.runtime.firebase.transport.g(cursorRawQuery.getLong(0), jE);
                                        cursorRawQuery.close();
                                        sQLiteDatabaseA.setTransactionSuccessful();
                                        sQLiteDatabaseA.endTransaction();
                                        hVar2.a = gVar4;
                                        hVar2.c = new com.google.android.datatransport.runtime.firebase.transport.b(new com.google.android.datatransport.runtime.firebase.transport.f(gVar3.a().compileStatement("PRAGMA page_size").simpleQueryForLong() * gVar3.a().compileStatement("PRAGMA page_count").simpleQueryForLong(), com.google.android.datatransport.runtime.scheduling.persistence.a.f.a));
                                        hVar2.d = (String) gVar3.e.get();
                                        return new com.google.android.datatransport.runtime.firebase.transport.a((com.google.android.datatransport.runtime.firebase.transport.g) hVar2.a, Collections.unmodifiableList((ArrayList) hVar2.b), (com.google.android.datatransport.runtime.firebase.transport.b) hVar2.c, (String) hVar2.d);
                                    } catch (Throwable th3) {
                                        cursorRawQuery.close();
                                        throw th3;
                                    }
                                } catch (Throwable th4) {
                                    sQLiteDatabaseA.endTransaction();
                                    throw th4;
                                }
                            }
                            Map.Entry entry2 = (Map.Entry) it2.next();
                            int i14 = com.google.android.datatransport.runtime.firebase.transport.e.c;
                            new ArrayList();
                            ((ArrayList) hVar2.b).add(new com.google.android.datatransport.runtime.firebase.transport.e((String) entry2.getKey(), Collections.unmodifiableList((List) entry2.getValue())));
                        }
                    }
                }
            default:
                com.quizlet.billing.model.a aVar2 = (com.quizlet.billing.model.a) obj;
                ((com.quizlet.billing.subscriptions.h) obj4).getClass();
                aVar2.a((Purchase) obj3);
                String sku = (String) obj2;
                Intrinsics.checkNotNullParameter(sku, "sku");
                Intrinsics.checkNotNullParameter(sku, "sku");
                return (com.quizlet.data.model.billing.a) aVar2.a.get(sku);
        }
    }

    @Override // androidx.camera.core.i0
    public void b(C0187j c0187j) {
        androidx.camera.view.j jVar;
        androidx.camera.view.e eVar = (androidx.camera.view.e) this.b;
        eVar.getClass();
        Objects.toString(c0187j);
        AbstractC3053s1.f(3, "PreviewView");
        boolean z = ((InterfaceC0185y) this.c).n().e() == 0;
        PreviewView previewView = eVar.a;
        Size size = ((androidx.camera.core.j0) this.d).b;
        androidx.camera.view.c cVar = previewView.d;
        cVar.getClass();
        Objects.toString(c0187j);
        Objects.toString(size);
        AbstractC3053s1.f(3, "PreviewTransform");
        cVar.b = c0187j.a;
        cVar.c = c0187j.b;
        int i = c0187j.c;
        cVar.e = i;
        cVar.a = size;
        cVar.f = z;
        cVar.g = c0187j.d;
        cVar.d = c0187j.e;
        if (i == -1 || ((jVar = previewView.b) != null && (jVar instanceof androidx.camera.view.q))) {
            previewView.e = true;
        } else {
            previewView.e = false;
        }
        previewView.a();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        eVar.dismiss();
        ((com.quizlet.offline.managers.i) this.b).a.I("warned_missing_offline_study_anyway");
        ((com.quizlet.qutils.rx.c) this.c).accept((Intent) this.d);
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i completer) {
        switch (this.a) {
            case 1:
                androidx.concurrent.futures.l lVar = (androidx.concurrent.futures.l) this.b;
                RunnableC0041m runnableC0041m = new RunnableC0041m(lVar, 15);
                androidx.camera.core.impl.utils.executor.k kVar = (androidx.camera.core.impl.utils.executor.k) this.c;
                completer.a(runnableC0041m, kVar);
                lVar.a(new androidx.camera.core.impl.utils.futures.h(0, lVar, new com.quizlet.data.repository.school.membership.a(completer, 6)), kVar);
                return android.support.v4.media.session.a.n("]", new StringBuilder("surfaceList["), (List) this.d);
            case 2:
                ((p0) this.b).getClass();
                InterfaceC0183w interfaceC0183w = (InterfaceC0183w) this.c;
                C0134k c0134k = new C0134k(completer, interfaceC0183w);
                ((ArrayList) this.d).add(c0134k);
                interfaceC0183w.b(com.google.android.gms.internal.mlkit_vision_barcode.T.a(), c0134k);
                return "waitForCaptureResult";
            default:
                Intrinsics.checkNotNullParameter(completer, "completer");
                AtomicBoolean atomicBoolean = new AtomicBoolean(false);
                completer.a(new androidx.work.r(atomicBoolean, 0), EnumC1440n.a);
                ((ExecutorC0060p) this.b).execute(new RunnableC0130g(atomicBoolean, completer, (Function0) this.d, 14));
                return (String) this.c;
        }
    }

    @Override // io.reactivex.rxjava3.core.c
    public void e(io.reactivex.rxjava3.internal.operators.completable.d dVar) {
        DiagramView.a((DiagramView) this.b, (DiagramData) this.c, (com.quizlet.diagrams.b[]) this.d, dVar);
    }

    public void f(JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = (JSONObject) this.d;
        com.onetrust.otpublishers.headless.UI.fragment.I i = (com.onetrust.otpublishers.headless.UI.fragment.I) this.b;
        com.onetrust.otpublishers.headless.UI.adapter.o oVar = new com.onetrust.otpublishers.headless.UI.adapter.o(jSONObject, i.Y, i.y1, (JSONObject) this.c, i.z1);
        try {
            if (retrofit2.adapter.rxjava3.d.o(jSONObject)) {
                i.M.setVisibility(8);
            }
            if (!retrofit2.adapter.rxjava3.d.o(jSONObject) && jSONObject.has("disclosures") && jSONObject.getJSONArray("disclosures").length() > 0) {
                i.M.setVisibility(0);
                i.J.setVisibility(0);
                i.k1.setLayoutManager(new LinearLayoutManager(i.X));
                i.k1.setAdapter(oVar);
            }
            JSONArray jSONArray = new JSONArray();
            if (jSONObject.has("domains")) {
                jSONArray = jSONObject.getJSONArray("domains");
            }
            if (retrofit2.adapter.rxjava3.d.l(jSONArray)) {
                return;
            }
            i.M.setVisibility(0);
            i.K.setVisibility(0);
            i.K.setText(jSONObject2.optString("PCVLSDomainsUsed"));
            com.onetrust.otpublishers.headless.UI.TVUI.adapter.p pVar = new com.onetrust.otpublishers.headless.UI.TVUI.adapter.p(jSONArray, jSONObject2, i.y1, i.z1);
            i.L.setLayoutManager(new LinearLayoutManager(i.X));
            i.L.setAdapter(pVar);
        } catch (JSONException e) {
            com.google.android.gms.internal.mlkit_vision_document_scanner.W.a("showVendorDisclosureDetails: ", e, "VendorDetail", 6);
        }
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        return ((FirebaseMessaging) this.b).lambda$blockingGetToken$13((String) this.c, (com.google.firebase.messaging.v) this.d, (String) obj);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        com.google.firebase.remoteconfig.internal.c cVar;
        URL url;
        switch (this.a) {
            case 12:
                boolean zL = task.l();
                com.google.android.gms.tasks.f fVar = (com.google.android.gms.tasks.f) this.b;
                if (zL) {
                    fVar.d(task.h());
                } else if (task.g() != null) {
                    fVar.c(task.g());
                } else if (((AtomicBoolean) this.c).getAndSet(true)) {
                    ((com.google.firebase.platforminfo.c) this.d).j();
                }
                return S3.i(null);
            case 13:
            default:
                com.google.firebase.remoteconfig.internal.h hVar = (com.google.firebase.remoteconfig.internal.h) this.b;
                hVar.getClass();
                com.google.android.gms.tasks.m mVar = (com.google.android.gms.tasks.m) this.c;
                if (!mVar.l()) {
                    return S3.h(new FirebaseRemoteConfigClientException("Firebase Installations failed to get installation auth token for config update listener connection.", mVar.g()));
                }
                com.google.android.gms.tasks.m mVar2 = (com.google.android.gms.tasks.m) this.d;
                try {
                    if (!mVar2.l()) {
                        return S3.h(new FirebaseRemoteConfigClientException("Firebase Installations failed to get installation ID for config update listener connection.", mVar2.g()));
                    }
                    try {
                        url = new URL(hVar.c(hVar.m));
                    } catch (MalformedURLException unused) {
                        Log.e("FirebaseRemoteConfig", "URL is malformed");
                        url = null;
                    }
                    HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
                    hVar.i(httpURLConnection, (String) mVar2.h(), ((com.google.firebase.installations.a) mVar.h()).a);
                    return S3.i(httpURLConnection);
                } catch (IOException e) {
                    return S3.h(new FirebaseRemoteConfigClientException("Failed to open HTTP stream connection", e));
                }
            case 14:
                com.google.firebase.remoteconfig.b bVar = (com.google.firebase.remoteconfig.b) this.b;
                bVar.getClass();
                Task task2 = (Task) this.c;
                if (!task2.l() || task2.h() == null) {
                    return S3.i(Boolean.FALSE);
                }
                com.google.firebase.remoteconfig.internal.c cVar2 = (com.google.firebase.remoteconfig.internal.c) task2.h();
                Task task3 = (Task) this.d;
                if (task3.l() && (cVar = (com.google.firebase.remoteconfig.internal.c) task3.h()) != null && cVar2.c.equals(cVar.c)) {
                    return S3.i(Boolean.FALSE);
                }
                com.google.firebase.remoteconfig.internal.b bVar2 = bVar.d;
                bVar2.getClass();
                androidx.work.impl.A a = new androidx.work.impl.A(4, bVar2, cVar2);
                Executor executor = bVar2.a;
                return S3.g(executor, a).n(executor, new C0143u(26, bVar2, cVar2)).e(bVar.b, new com.google.firebase.remoteconfig.a(bVar));
        }
    }

    public void i() {
        BrazeInAppMessageManager.displayInAppMessage$lambda$51((IInAppMessageViewWrapper) this.b, (BrazeInAppMessageManager) this.c, (Activity) this.d);
    }

    @Override // io.reactivex.rxjava3.core.r
    public void j(io.reactivex.rxjava3.internal.operators.single.c cVar) {
        com.quizlet.infra.legacysyncengine.net.c cVar2 = (com.quizlet.infra.legacysyncengine.net.c) this.b;
        cVar2.getClass();
        com.quizlet.infra.legacysyncengine.datasources.f fVar = new com.quizlet.infra.legacysyncengine.datasources.f(cVar, 6);
        com.quizlet.infra.legacysyncengine.orm.query.a aVar = (com.quizlet.infra.legacysyncengine.orm.query.a) this.c;
        cVar2.e(aVar, fVar);
        io.reactivex.rxjava3.internal.disposables.a.d(cVar, new io.reactivex.rxjava3.disposables.d(new com.quizlet.infra.legacysyncengine.features.properties.b(cVar2, aVar, fVar, 3), 1));
        cVar2.c(aVar, Collections.singleton((com.quizlet.infra.legacysyncengine.net.b) this.d));
    }

    public void k() {
        p0 p0Var;
        AtomicReference atomicReference = ((androidx.camera.view.e) this.b).a.g;
        while (true) {
            p0Var = (p0) this.c;
            if (atomicReference.compareAndSet(p0Var, null)) {
                p0Var.n(androidx.camera.view.i.a);
                break;
            } else if (atomicReference.get() != p0Var) {
                break;
            }
        }
        androidx.camera.core.impl.utils.futures.d dVar = (androidx.camera.core.impl.utils.futures.d) p0Var.f;
        if (dVar != null) {
            dVar.cancel(false);
            p0Var.f = null;
        }
        ((InterfaceC0185y) this.d).f().b(p0Var);
    }

    @Override // io.reactivex.rxjava3.core.j
    public void l(C4899s c4899s) {
        com.quizlet.infra.legacysyncengine.net.c cVar = (com.quizlet.infra.legacysyncengine.net.c) this.b;
        cVar.getClass();
        com.quizlet.infra.legacysyncengine.datasources.q qVar = new com.quizlet.infra.legacysyncengine.datasources.q(c4899s, 5);
        com.quizlet.infra.legacysyncengine.orm.query.a aVar = (com.quizlet.infra.legacysyncengine.orm.query.a) this.c;
        cVar.e(aVar, qVar);
        c4899s.d(new com.quizlet.infra.legacysyncengine.features.properties.b(cVar, aVar, qVar, 2));
        new C4905y(cVar.c(aVar, (Set) this.d), new com.quizlet.eventlogger.e(c4899s, 13), 1).t();
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTNetworkRequestCallback
    public void onCompletion(boolean z) {
        com.onetrust.otpublishers.headless.Internal.Network.d dVar = (com.onetrust.otpublishers.headless.Internal.Network.d) this.b;
        if (z) {
            dVar.getClass();
        } else {
            dVar.e((String) this.c, (String) this.d, false, null);
        }
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        Task task = (Task) this.c;
        com.google.firebase.crashlytics.internal.b bVar = (com.google.firebase.crashlytics.internal.b) this.d;
        com.quizlet.data.repository.explanations.question.a aVar = (com.quizlet.data.repository.explanations.question.a) this.b;
        try {
            com.google.firebase.remoteconfig.internal.c cVar = (com.google.firebase.remoteconfig.internal.c) task.h();
            if (cVar != null) {
                ((Executor) aVar.c).execute(new com.google.firebase.remoteconfig.internal.rollouts.a(bVar, ((androidx.work.impl.model.l) aVar.b).j(cVar), 1));
            }
        } catch (FirebaseRemoteConfigException e) {
            Log.w("FirebaseRemoteConfig", "Exception publishing RolloutsState to subscriber. Continuing to listen for changes.", e);
        }
    }

    @Override // androidx.fragment.app.m0
    public void y(Bundle result, String requestKey) {
        Intrinsics.checkNotNullParameter(requestKey, "requestKey");
        Intrinsics.checkNotNullParameter(result, "result");
        if (requestKey.hashCode() == 1944357242 && requestKey.equals("onboardingELLRequestKey")) {
            if (result.getBoolean("onboardingELLUpdateHomeResultKey")) {
                E4.h((androidx.navigation.H) this.b, (Function1) this.c);
            }
            ((com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L) this.d).p.h(com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.r.a);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x0140 A[Catch: all -> 0x0041, TryCatch #0 {all -> 0x0041, blocks: (B:4:0x001d, B:9:0x002b, B:10:0x003f, B:14:0x0044, B:15:0x004a, B:17:0x0050, B:18:0x0065, B:19:0x00c3, B:21:0x00c9, B:22:0x00de, B:24:0x00ee, B:26:0x00f2, B:27:0x00fe, B:28:0x0116, B:30:0x011c, B:32:0x012a, B:34:0x0132, B:38:0x0140, B:40:0x0152, B:42:0x0168, B:43:0x0173, B:45:0x0193, B:47:0x0197, B:48:0x01a0, B:49:0x01c1, B:51:0x01c7, B:52:0x01d7, B:54:0x01ef, B:55:0x01f4, B:56:0x01fc, B:59:0x01ff, B:60:0x0205, B:62:0x0207, B:63:0x021c), top: B:67:0x001d, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0166  */
    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.common.util.concurrent.e apply(java.lang.Object r21) {
        /*
            Method dump skipped, instructions count: 544
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.T.apply(java.lang.Object):com.google.common.util.concurrent.e");
    }
}
