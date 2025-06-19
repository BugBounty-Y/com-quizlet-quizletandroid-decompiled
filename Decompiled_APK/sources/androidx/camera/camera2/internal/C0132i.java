package androidx.camera.camera2.internal;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;
import androidx.camera.core.impl.C0186z;
import androidx.credentials.playservices.HiddenActivity;
import com.braze.models.cards.ICardListener;
import com.comscore.streaming.EventType;
import com.comscore.util.log.LogLevel;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_common.R2;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.encoders.EncodingException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.camera.camera2.internal.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0132i implements androidx.concurrent.futures.j, androidx.camera.core.impl.Q, androidx.camera.core.impl.utils.futures.a, androidx.arch.core.util.a, com.google.android.gms.tasks.d, OnCompleteListener, ICardListener, com.facebook.appevents.internal.k, com.google.android.datatransport.runtime.synchronization.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0132i(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.datatransport.runtime.synchronization.a
    public Object a() {
        SQLiteDatabase sQLiteDatabaseA;
        Object obj = this.b;
        switch (this.a) {
            case EventType.CDN /* 26 */:
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar = (com.google.android.datatransport.runtime.scheduling.persistence.g) ((com.google.android.datatransport.runtime.scheduling.persistence.c) obj);
                gVar.getClass();
                int i = com.google.android.datatransport.runtime.firebase.transport.a.e;
                com.quizlet.data.repository.achievements.h hVar = new com.quizlet.data.repository.achievements.h();
                hVar.a = null;
                hVar.b = new ArrayList();
                hVar.c = null;
                hVar.d = "";
                HashMap map = new HashMap();
                sQLiteDatabaseA = gVar.a();
                sQLiteDatabaseA.beginTransaction();
                try {
                    com.google.android.datatransport.runtime.firebase.transport.a aVar = (com.google.android.datatransport.runtime.firebase.transport.a) com.google.android.datatransport.runtime.scheduling.persistence.g.q(sQLiteDatabaseA.rawQuery("SELECT log_source, reason, events_dropped_count FROM log_event_dropped", new String[0]), new T(gVar, map, hVar, 11));
                    sQLiteDatabaseA.setTransactionSuccessful();
                    return aVar;
                } finally {
                }
            case 27:
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar2 = (com.google.android.datatransport.runtime.scheduling.persistence.g) ((com.google.android.datatransport.runtime.scheduling.persistence.d) obj);
                long jE = gVar2.b.e() - gVar2.d.d;
                sQLiteDatabaseA = gVar2.a();
                sQLiteDatabaseA.beginTransaction();
                try {
                    String[] strArr = {String.valueOf(jE)};
                    Cursor cursorRawQuery = sQLiteDatabaseA.rawQuery("SELECT COUNT(*), transport_name FROM events WHERE timestamp_ms < ? GROUP BY transport_name", strArr);
                    while (cursorRawQuery.moveToNext()) {
                        try {
                            gVar2.j(cursorRawQuery.getInt(0), com.google.android.datatransport.runtime.firebase.transport.c.MESSAGE_TOO_OLD, cursorRawQuery.getString(1));
                        } catch (Throwable th) {
                            cursorRawQuery.close();
                            throw th;
                        }
                    }
                    cursorRawQuery.close();
                    int iDelete = sQLiteDatabaseA.delete("events", "timestamp_ms < ?", strArr);
                    sQLiteDatabaseA.setTransactionSuccessful();
                    sQLiteDatabaseA.endTransaction();
                    return Integer.valueOf(iDelete);
                } finally {
                }
            default:
                com.google.android.datatransport.runtime.scheduling.persistence.g gVar3 = (com.google.android.datatransport.runtime.scheduling.persistence.g) ((com.google.android.datatransport.runtime.scheduling.jobscheduling.i) obj).i;
                sQLiteDatabaseA = gVar3.a();
                sQLiteDatabaseA.beginTransaction();
                try {
                    sQLiteDatabaseA.compileStatement("DELETE FROM log_event_dropped").execute();
                    sQLiteDatabaseA.compileStatement("UPDATE global_log_event_state SET last_metrics_upload_ms=" + gVar3.b.e()).execute();
                    sQLiteDatabaseA.setTransactionSuccessful();
                    return null;
                } finally {
                }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public com.google.common.util.concurrent.e apply(Object obj) {
        androidx.camera.lifecycle.f tmp0 = (androidx.camera.lifecycle.f) this.b;
        Intrinsics.checkNotNullParameter(tmp0, "$tmp0");
        return (com.google.common.util.concurrent.e) tmp0.invoke(obj);
    }

    public C0186z b(com.quizlet.data.repository.login.a aVar) throws IOException {
        com.google.android.datatransport.cct.b bVar = (com.google.android.datatransport.cct.b) this.b;
        String strConcat = "TRuntime.".concat("CctTransportBackend");
        boolean zIsLoggable = Log.isLoggable(strConcat, 4);
        URL url = (URL) aVar.a;
        if (zIsLoggable) {
            Log.i(strConcat, String.format("Making request to: %s", url));
        }
        HttpURLConnection httpURLConnection = (HttpURLConnection) url.openConnection();
        httpURLConnection.setConnectTimeout(LogLevel.NONE);
        httpURLConnection.setReadTimeout(bVar.g);
        httpURLConnection.setDoOutput(true);
        httpURLConnection.setInstanceFollowRedirects(false);
        httpURLConnection.setRequestMethod("POST");
        httpURLConnection.setRequestProperty("User-Agent", "datatransport/3.3.0 android/");
        httpURLConnection.setRequestProperty("Content-Encoding", "gzip");
        httpURLConnection.setRequestProperty("Content-Type", "application/json");
        httpURLConnection.setRequestProperty("Accept-Encoding", "gzip");
        String str = (String) aVar.c;
        if (str != null) {
            httpURLConnection.setRequestProperty("X-Goog-Api-Key", str);
        }
        try {
            OutputStream outputStream = httpURLConnection.getOutputStream();
            try {
                GZIPOutputStream gZIPOutputStream = new GZIPOutputStream(outputStream);
                try {
                    androidx.webkit.internal.p pVar = bVar.a;
                    com.google.android.datatransport.cct.internal.m mVar = (com.google.android.datatransport.cct.internal.m) aVar.b;
                    BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(gZIPOutputStream));
                    com.google.firebase.encoders.json.d dVar = (com.google.firebase.encoders.json.d) pVar.b;
                    com.google.firebase.encoders.json.e eVar = new com.google.firebase.encoders.json.e(bufferedWriter, dVar.a, dVar.b, dVar.c, dVar.d);
                    eVar.h(mVar);
                    eVar.j();
                    eVar.b.flush();
                    gZIPOutputStream.close();
                    if (outputStream != null) {
                        outputStream.close();
                    }
                    int responseCode = httpURLConnection.getResponseCode();
                    Integer numValueOf = Integer.valueOf(responseCode);
                    String strConcat2 = "TRuntime.".concat("CctTransportBackend");
                    if (Log.isLoggable(strConcat2, 4)) {
                        Log.i(strConcat2, String.format("Status Code: %d", numValueOf));
                    }
                    R2.c("CctTransportBackend", "Content-Type: %s", httpURLConnection.getHeaderField("Content-Type"));
                    R2.c("CctTransportBackend", "Content-Encoding: %s", httpURLConnection.getHeaderField("Content-Encoding"));
                    if (responseCode == 302 || responseCode == 301 || responseCode == 307) {
                        return new C0186z(responseCode, new URL(httpURLConnection.getHeaderField("Location")), 0L);
                    }
                    if (responseCode != 200) {
                        return new C0186z(responseCode, (URL) null, 0L);
                    }
                    InputStream inputStream = httpURLConnection.getInputStream();
                    try {
                        InputStream gZIPInputStream = "gzip".equals(httpURLConnection.getHeaderField("Content-Encoding")) ? new GZIPInputStream(inputStream) : inputStream;
                        try {
                            C0186z c0186z = new C0186z(responseCode, (URL) null, com.google.android.datatransport.cct.internal.v.a(new BufferedReader(new InputStreamReader(gZIPInputStream))).a);
                            if (gZIPInputStream != null) {
                                gZIPInputStream.close();
                            }
                            if (inputStream != null) {
                                inputStream.close();
                            }
                            return c0186z;
                        } finally {
                        }
                    } finally {
                    }
                } finally {
                }
            } finally {
            }
        } catch (EncodingException e) {
            e = e;
            R2.d("CctTransportBackend", "Couldn't encode request, returning with 400", e);
            return new C0186z(400, (URL) null, 0L);
        } catch (ConnectException e2) {
            e = e2;
            R2.d("CctTransportBackend", "Couldn't open connection, returning with 500", e);
            return new C0186z(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, (URL) null, 0L);
        } catch (UnknownHostException e3) {
            e = e3;
            R2.d("CctTransportBackend", "Couldn't open connection, returning with 500", e);
            return new C0186z(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, (URL) null, 0L);
        } catch (IOException e4) {
            e = e4;
            R2.d("CctTransportBackend", "Couldn't encode request, returning with 400", e);
            return new C0186z(400, (URL) null, 0L);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:46:0x0109  */
    @Override // com.facebook.appevents.internal.k
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void c(java.io.File r20) {
        /*
            Method dump skipped, instructions count: 405
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.internal.C0132i.c(java.io.File):void");
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i completer) {
        switch (this.a) {
            case 0:
                C0137n c0137n = (C0137n) this.b;
                c0137n.getClass();
                c0137n.c.execute(new androidx.activity.r(2, c0137n, completer));
                return "updateSessionConfigAsync";
            case 3:
                C0135l c0135l = (C0135l) this.b;
                c0135l.c = completer;
                return "RequestCompleteListener[" + c0135l + "]";
            case 7:
                androidx.camera.core.processing.j jVar = (androidx.camera.core.processing.j) this.b;
                jVar.p = completer;
                return "SettableFuture hashCode: " + jVar.hashCode();
            case 8:
                ((androidx.camera.core.processing.l) this.b).k = completer;
                return "SurfaceOutputImpl close future complete";
            case 11:
                ((androidx.camera.view.s) this.b).k.set(completer);
                return "textureViewImpl_waitForNextFrame";
            default:
                kotlinx.coroutines.I this_asListenableFuture = (kotlinx.coroutines.I) this.b;
                Intrinsics.checkNotNullParameter(this_asListenableFuture, "$this_asListenableFuture");
                Intrinsics.checkNotNullParameter(completer, "completer");
                this_asListenableFuture.Q(new androidx.compose.ui.viewinterop.b(6, completer, this_asListenableFuture));
                return "Deferred.asListenableFuture";
        }
    }

    @Override // androidx.camera.core.impl.Q
    public void e(androidx.camera.core.impl.S s) throws Exception {
        switch (this.a) {
            case 2:
                t0 t0Var = (t0) this.b;
                t0Var.getClass();
                try {
                    androidx.camera.core.O oL = s.l();
                    if (oL != null) {
                        ((com.quizlet.data.repository.user.a) t0Var.e).o(oL);
                        return;
                    }
                    return;
                } catch (IllegalStateException e) {
                    AbstractC3053s1.c("ZslControlImpl", "Failed to acquire latest image IllegalStateException = " + e.getMessage());
                    return;
                }
            case 5:
                androidx.camera.core.T t = (androidx.camera.core.T) this.b;
                synchronized (t.a) {
                    t.c++;
                }
                t.e(s);
                return;
            default:
                ((androidx.work.impl.model.v) this.b).getClass();
                try {
                    androidx.camera.core.O oL2 = s.l();
                    if (oL2 != null) {
                        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
                        AbstractC3053s1.h("CaptureNode", "Discarding ImageProxy which was inadvertently acquired: " + oL2);
                        oL2.close();
                        return;
                    }
                    return;
                } catch (IllegalStateException unused) {
                    return;
                }
        }
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Iterable, java.lang.Object] */
    public void f() {
        switch (this.a) {
            case 12:
                androidx.compose.ui.viewinterop.b bVar = (androidx.compose.ui.viewinterop.b) this.b;
                synchronized (androidx.compose.runtime.snapshots.m.b) {
                    androidx.compose.runtime.snapshots.m.h = CollectionsKt.a0(androidx.compose.runtime.snapshots.m.h, bVar);
                    Unit unit = Unit.a;
                }
                androidx.compose.runtime.snapshots.m.a();
                return;
            default:
                kotlin.jvm.internal.r rVar = (kotlin.jvm.internal.r) this.b;
                synchronized (androidx.compose.runtime.snapshots.m.b) {
                    androidx.compose.runtime.snapshots.m.g = CollectionsKt.a0(androidx.compose.runtime.snapshots.m.g, rVar);
                    Unit unit2 = Unit.a;
                }
                return;
        }
    }

    public float g(float f) {
        return ((androidx.constraintlayout.compose.k) this.b).k.a() * f;
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        com.braze.managers.b0.a((com.braze.managers.b0) this.b, task);
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        Object obj2 = this.b;
        switch (this.a) {
            case 16:
                ((androidx.credentials.playservices.d) obj2).invoke(obj);
                break;
            case 17:
                int i = HiddenActivity.c;
                ((androidx.credentials.playservices.f) obj2).invoke(obj);
                break;
            case 18:
                int i2 = HiddenActivity.c;
                ((androidx.credentials.playservices.f) obj2).invoke(obj);
                break;
            case 19:
                int i3 = HiddenActivity.c;
                ((androidx.credentials.playservices.f) obj2).invoke(obj);
                break;
            default:
                int i4 = HiddenActivity.c;
                ((androidx.credentials.playservices.f) obj2).invoke(obj);
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ C0132i(Function2 function2) {
        this.a = 13;
        this.b = (kotlin.jvm.internal.r) function2;
    }

    @Override // androidx.arch.core.util.a
    /* renamed from: apply, reason: collision with other method in class */
    public Object mo0apply(Object obj) {
        androidx.camera.lifecycle.d tmp0 = (androidx.camera.lifecycle.d) this.b;
        Intrinsics.checkNotNullParameter(tmp0, "$tmp0");
        return (androidx.camera.lifecycle.g) tmp0.invoke(obj);
    }
}
