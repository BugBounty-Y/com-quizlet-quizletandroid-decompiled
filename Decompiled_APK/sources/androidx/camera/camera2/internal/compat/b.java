package androidx.camera.camera2.internal.compat;

import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CaptureFailure;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.CaptureResult;
import android.hardware.camera2.TotalCaptureResult;
import android.util.Log;
import android.view.Surface;
import androidx.appcompat.app.K;
import androidx.camera.camera2.internal.C0135l;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.j0;
import androidx.work.C1422c;
import androidx.work.impl.InterfaceC1435g;
import androidx.work.impl.WorkDatabase;
import com.facebook.appevents.iap.u;
import com.facebook.internal.J;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.quizlet.eventlogger.model.EditActionsLog;
import com.quizlet.generated.enums.O1;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicMarkableReference;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ b(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r0v12 */
    /* JADX WARN: Type inference failed for: r0v13 */
    /* JADX WARN: Type inference failed for: r0v14 */
    /* JADX WARN: Type inference failed for: r0v16, types: [javax.net.ssl.HttpsURLConnection] */
    /* JADX WARN: Type inference failed for: r0v17 */
    /* JADX WARN: Type inference failed for: r0v22, types: [java.net.HttpURLConnection, java.net.URLConnection, javax.net.ssl.HttpsURLConnection] */
    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        HttpsURLConnection httpsURLConnection;
        String[] strArrF;
        ?? r0 = "$completionHandler";
        BufferedOutputStream bufferedOutputStream = null;
        BufferedInputStream bufferedInputStream = null;
        obj = null;
        obj = null;
        Object obj = null;
        Object obj2 = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        bufferedInputStream = null;
        Object obj3 = this.d;
        Object obj4 = this.e;
        Object obj5 = this.c;
        Object obj6 = this.b;
        switch (this.a) {
            case 0:
                ((CameraCaptureSession.CaptureCallback) ((C0135l) obj6).b).onCaptureCompleted((CameraCaptureSession) obj5, (CaptureRequest) obj3, (TotalCaptureResult) obj4);
                return;
            case 1:
                ((CameraCaptureSession.CaptureCallback) ((C0135l) obj6).b).onCaptureProgressed((CameraCaptureSession) obj5, (CaptureRequest) obj3, (CaptureResult) obj4);
                return;
            case 2:
                ((CameraCaptureSession.CaptureCallback) ((C0135l) obj6).b).onCaptureFailed((CameraCaptureSession) obj5, (CaptureRequest) obj3, (CaptureFailure) obj4);
                return;
            case 3:
                androidx.camera.view.s sVar = (androidx.camera.view.s) obj6;
                sVar.getClass();
                AbstractC3053s1.f(3, "TextureViewImpl");
                T t = sVar.l;
                if (t != null) {
                    t.k();
                    sVar.l = null;
                }
                ((Surface) obj5).release();
                if (sVar.g == ((androidx.concurrent.futures.l) obj3)) {
                    sVar.g = null;
                }
                if (sVar.h == ((j0) obj4)) {
                    sVar.h = null;
                    return;
                }
                return;
            case 4:
                List list = (List) obj6;
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    ((InterfaceC1435g) it2.next()).e(((androidx.work.impl.model.j) obj5).a);
                }
                androidx.work.impl.i.b((C1422c) obj3, (WorkDatabase) obj4, list);
                return;
            case 5:
                String str = (String) obj5;
                String str2 = (String) obj3;
                String str3 = (String) obj4;
                ((K) obj6).getClass();
                try {
                    try {
                        r0 = (HttpsURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(new URL(str).openConnection()));
                        try {
                            if (K.H(r0, str2)) {
                                bufferedOutputStream = new BufferedOutputStream(r0.getOutputStream());
                                try {
                                    bufferedOutputStream.write(str3.getBytes());
                                    bufferedOutputStream.flush();
                                    int responseCode = r0.getResponseCode();
                                    httpsURLConnection = r0;
                                    if (responseCode == 200) {
                                        byte[] bArr = new byte[1024];
                                        BufferedInputStream bufferedInputStream2 = new BufferedInputStream(r0.getInputStream());
                                        try {
                                            bufferedInputStream2.read(bArr);
                                            new String(bArr);
                                            K.o(bufferedInputStream2, bufferedOutputStream, r0);
                                            return;
                                        } catch (IOException e) {
                                            e = e;
                                            bufferedInputStream = bufferedInputStream2;
                                            Log.e("K", "Error in sendData: ", e);
                                            httpsURLConnection = r0;
                                            K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                                            return;
                                        } catch (RuntimeException e2) {
                                            e = e2;
                                            bufferedInputStream = bufferedInputStream2;
                                            Log.e("K", "Error in sendData: ", e);
                                            httpsURLConnection = r0;
                                            K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                                            return;
                                        } catch (Throwable th) {
                                            th = th;
                                            bufferedInputStream = bufferedInputStream2;
                                            K.o(bufferedInputStream, bufferedOutputStream, r0);
                                            throw th;
                                        }
                                    }
                                } catch (IOException e3) {
                                    e = e3;
                                } catch (RuntimeException e4) {
                                    e = e4;
                                }
                            } else {
                                bufferedOutputStream = null;
                                httpsURLConnection = r0;
                            }
                        } catch (IOException e5) {
                            e = e5;
                            bufferedOutputStream = null;
                            Log.e("K", "Error in sendData: ", e);
                            httpsURLConnection = r0;
                            K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                            return;
                        } catch (RuntimeException e6) {
                            e = e6;
                            bufferedOutputStream = null;
                            Log.e("K", "Error in sendData: ", e);
                            httpsURLConnection = r0;
                            K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                            return;
                        } catch (Throwable th2) {
                            th = th2;
                            bufferedOutputStream = null;
                        }
                    } catch (Throwable th3) {
                        th = th3;
                    }
                } catch (IOException e7) {
                    e = e7;
                    r0 = 0;
                    bufferedOutputStream = null;
                    Log.e("K", "Error in sendData: ", e);
                    httpsURLConnection = r0;
                    K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                    return;
                } catch (RuntimeException e8) {
                    e = e8;
                    r0 = 0;
                    bufferedOutputStream = null;
                    Log.e("K", "Error in sendData: ", e);
                    httpsURLConnection = r0;
                    K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                    return;
                } catch (Throwable th4) {
                    th = th4;
                    r0 = 0;
                    bufferedOutputStream = null;
                }
                K.o(bufferedInputStream, bufferedOutputStream, httpsURLConnection);
                return;
            case 6:
                com.facebook.appevents.iap.l this$0 = (com.facebook.appevents.iap.l) obj6;
                Runnable completionHandler = (Runnable) obj5;
                com.facebook.appevents.iap.t skuType = (com.facebook.appevents.iap.t) obj3;
                ArrayList skuIDs = (ArrayList) obj4;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.l.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(this$0, "this$0");
                    Intrinsics.checkNotNullParameter(completionHandler, "$completionHandler");
                    Intrinsics.checkNotNullParameter(skuType, "$skuType");
                    Intrinsics.checkNotNullParameter(skuIDs, "$skuIDs");
                    Object objNewProxyInstance = Proxy.newProxyInstance(this$0.e.getClassLoader(), new Class[]{this$0.e}, new com.facebook.appevents.iap.k(this$0, completionHandler));
                    Object objA = this$0.k.a(skuType, skuIDs);
                    Class cls = this$0.b;
                    Method method = this$0.i;
                    if (!com.facebook.internal.instrument.crashshield.a.b(this$0)) {
                        try {
                            obj2 = this$0.a;
                        } catch (Throwable th5) {
                            com.facebook.internal.instrument.crashshield.a.a(this$0, th5);
                        }
                    }
                    u.h(cls, obj2, method, objA, objNewProxyInstance);
                    return;
                } catch (Throwable th6) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.l.class, th6);
                    return;
                }
            case 7:
                com.facebook.appevents.iap.m this$02 = (com.facebook.appevents.iap.m) obj6;
                Runnable completionHandler2 = (Runnable) obj5;
                com.facebook.appevents.iap.t productType = (com.facebook.appevents.iap.t) obj3;
                ArrayList productIds = (ArrayList) obj4;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.iap.m.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(this$02, "this$0");
                    Intrinsics.checkNotNullParameter(completionHandler2, "$completionHandler");
                    Intrinsics.checkNotNullParameter(productType, "$productType");
                    Intrinsics.checkNotNullParameter(productIds, "$productIds");
                    Object objNewProxyInstance2 = Proxy.newProxyInstance(this$02.n.getClassLoader(), new Class[]{this$02.n}, new com.facebook.appevents.iap.k(this$02, new Object[]{completionHandler2}));
                    Object objE = this$02.e(productType, productIds);
                    if (objE != null) {
                        Class cls2 = this$02.b;
                        Method method2 = this$02.v;
                        if (!com.facebook.internal.instrument.crashshield.a.b(this$02)) {
                            try {
                                obj = this$02.a;
                            } catch (Throwable th7) {
                                com.facebook.internal.instrument.crashshield.a.a(this$02, th7);
                            }
                        }
                        u.h(cls2, obj, method2, objE, objNewProxyInstance2);
                        return;
                    }
                    return;
                } catch (Throwable th8) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.iap.m.class, th8);
                    return;
                }
            case 8:
                JSONObject viewData = (JSONObject) obj6;
                String buttonText = (String) obj5;
                com.facebook.appevents.suggestedevents.f this$03 = (com.facebook.appevents.suggestedevents.f) obj3;
                String pathID = (String) obj4;
                if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.suggestedevents.f.class)) {
                    return;
                }
                try {
                    Intrinsics.checkNotNullParameter(viewData, "$viewData");
                    Intrinsics.checkNotNullParameter(buttonText, "$buttonText");
                    Intrinsics.checkNotNullParameter(this$03, "this$0");
                    Intrinsics.checkNotNullParameter(pathID, "$pathID");
                    try {
                        String lowerCase = J.m(com.facebook.o.a()).toLowerCase();
                        Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase()");
                        float[] fArrC = com.facebook.appevents.suggestedevents.a.c(lowerCase, viewData);
                        String strE = com.facebook.appevents.suggestedevents.a.e(buttonText, this$03.d, lowerCase);
                        if (fArrC != null && (strArrF = com.facebook.appevents.ml.e.f(com.facebook.appevents.ml.c.b, new float[][]{fArrC}, new String[]{strE})) != null) {
                            String str4 = strArrF[0];
                            com.facebook.appevents.suggestedevents.b.a(pathID, str4);
                            if (Intrinsics.b(str4, "other")) {
                                return;
                            }
                            HashSet hashSet = com.facebook.appevents.suggestedevents.f.e;
                            com.facebook.appevents.suggestedevents.a.j(str4, buttonText, fArrC);
                            return;
                        }
                        return;
                    } catch (Exception unused) {
                        return;
                    }
                } catch (Throwable th9) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.suggestedevents.f.class, th9);
                    return;
                }
            case 9:
                com.google.android.datatransport.runtime.i iVar = (com.google.android.datatransport.runtime.i) obj5;
                String str5 = iVar.a;
                com.google.android.datatransport.g gVar = (com.google.android.datatransport.g) obj3;
                com.google.android.datatransport.runtime.h hVar = (com.google.android.datatransport.runtime.h) obj4;
                com.google.android.datatransport.runtime.scheduling.a aVar = (com.google.android.datatransport.runtime.scheduling.a) obj6;
                aVar.getClass();
                Logger logger = com.google.android.datatransport.runtime.scheduling.a.f;
                try {
                    com.google.android.datatransport.runtime.backends.h hVarA = aVar.c.a(str5);
                    if (hVarA == null) {
                        String str6 = "Transport backend '" + str5 + "' is not registered";
                        logger.warning(str6);
                        gVar.b(new IllegalArgumentException(str6));
                    } else {
                        ((com.google.android.datatransport.runtime.scheduling.persistence.g) aVar.e).l(new T(aVar, iVar, ((com.google.android.datatransport.cct.b) hVarA).a(hVar), 8));
                        gVar.b(null);
                    }
                    return;
                } catch (Exception e9) {
                    logger.warning("Error scheduling event " + e9.getMessage());
                    gVar.b(e9);
                    return;
                }
            case 10:
                com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) obj6;
                String str7 = (String) ((AtomicMarkableReference) dVar.g).getReference();
                String str8 = (String) obj5;
                com.google.firebase.crashlytics.internal.metadata.h hVar2 = (com.google.firebase.crashlytics.internal.metadata.h) dVar.a;
                if (str7 != null) {
                    hVar2.j(str8, (String) ((AtomicMarkableReference) dVar.g).getReference());
                }
                Map map = (Map) obj3;
                if (!map.isEmpty()) {
                    hVar2.h(str8, map, false);
                }
                List list2 = (List) obj4;
                if (list2.isEmpty()) {
                    return;
                }
                hVar2.i(str8, list2);
                return;
            default:
                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar2 = ((com.quizlet.quizletandroid.ui.setcreation.managers.k) obj6).i;
                O1 o1 = (O1) obj5;
                String requestId = (String) obj4;
                if (requestId != null) {
                    com.quizlet.quizletandroid.sessionhelpers.a aVar2 = dVar2.m;
                    aVar2.getClass();
                    EditActionsLog editActionsLogA = aVar2.a(o1 == O1.DEFINITION ? "auto_lang_def" : "auto_lang_word", null, null);
                    Intrinsics.checkNotNullParameter(requestId, "requestId");
                    editActionsLogA.getPayload().setPredictionRequestUuid(requestId);
                    editActionsLogA.getPayload().setPredictionSelectionDepth(0);
                    editActionsLogA.d();
                }
                String str9 = (String) obj3;
                dVar2.y.f(o1, str9, true);
                dVar2.B.g0(o1, dVar2.q.a(str9));
                return;
        }
    }
}
