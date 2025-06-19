package androidx.webkit.internal;

import android.app.Activity;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Bundle;
import android.os.Parcel;
import android.text.TextUtils;
import android.util.Log;
import android.view.accessibility.AccessibilityNodeInfo;
import android.widget.TextView;
import androidx.camera.camera2.internal.compat.quirk.ExtraSupportedSurfaceCombinationsQuirk;
import androidx.camera.camera2.internal.p0;
import androidx.collection.C0219q;
import androidx.compose.material3.C0591b1;
import androidx.core.app.WindowOnFrameMetricsAvailableListenerC1022i;
import androidx.datastore.core.l0;
import androidx.datastore.core.o0;
import com.bumptech.glide.load.resource.bitmap.DefaultImageHeaderParser$Reader$EndOfFileException;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1939ct;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.zzyb;
import com.google.android.gms.measurement.internal.EnumC3866f;
import com.google.android.gms.measurement.internal.EnumC3879l0;
import com.google.android.gms.measurement.internal.K;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;
import org.chromium.support_lib_boundary.WebMessageListenerBoundaryInterface;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class p implements WebMessageListenerBoundaryInterface, androidx.compose.ui.text.input.s, com.bumptech.glide.util.pool.a, com.bumptech.glide.load.resource.bitmap.k, OnCompleteListener, com.google.android.gms.common.api.internal.i, K, com.google.firebase.crashlytics.internal.analytics.b, com.google.firebase.crashlytics.internal.breadcrumbs.a, com.google.mlkit.vision.barcode.common.internal.a {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ p(int i, boolean z) {
        this.a = i;
    }

    public static p r(int i, int i2, int i3, int i4, boolean z) {
        return new p(AccessibilityNodeInfo.CollectionItemInfo.obtain(i, i2, i3, i4, false, z), 8);
    }

    public static String v(Bundle bundle, String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        JSONObject jSONObject2 = new JSONObject();
        for (String str2 : bundle.keySet()) {
            jSONObject2.put(str2, bundle.get(str2));
        }
        jSONObject.put("name", str);
        jSONObject.put("parameters", jSONObject2);
        return jSONObject.toString();
    }

    @Override // com.google.android.gms.measurement.internal.K
    public void a(String str, int i, IOException iOException, byte[] bArr, Map map) {
        ((r1) this.b).t(str, i, iOException, bArr, map);
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.internal.p000authapi.b bVar = (com.google.android.gms.internal.p000authapi.b) this.b;
        bVar.getClass();
        com.google.android.gms.internal.p000authapi.c cVar = new com.google.android.gms.internal.p000authapi.c((com.google.android.gms.tasks.f) obj2);
        com.google.android.gms.internal.p000authapi.m mVar = (com.google.android.gms.internal.p000authapi.m) ((com.google.android.gms.internal.p000authapi.d) obj).m();
        Parcel parcelX = mVar.X();
        int i = com.google.android.gms.internal.p000authapi.h.a;
        parcelX.writeStrongBinder(cVar);
        parcelX.writeString(bVar.l);
        mVar.f0(2, parcelX);
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public int b() {
        return (o() << 8) | o();
    }

    @Override // com.bumptech.glide.util.pool.a
    public Object c() {
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = (com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.b;
        return new com.bumptech.glide.load.engine.o((com.bumptech.glide.load.engine.executor.e) dVar.a, (com.bumptech.glide.load.engine.executor.e) dVar.b, (com.bumptech.glide.load.engine.executor.e) dVar.c, (com.bumptech.glide.load.engine.executor.e) dVar.d, (com.bumptech.glide.load.engine.l) dVar.e, (com.bumptech.glide.load.engine.l) dVar.f, (com.quizlet.data.repository.course.membership.c) dVar.g);
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public Rect d() {
        Point[] pointArr = ((zzyb) this.b).e;
        if (pointArr == null) {
            return null;
        }
        int iMax = Integer.MIN_VALUE;
        int iMin = Integer.MAX_VALUE;
        int iMin2 = Integer.MAX_VALUE;
        int iMax2 = Integer.MIN_VALUE;
        for (Point point : pointArr) {
            iMin = Math.min(iMin, point.x);
            iMax = Math.max(iMax, point.x);
            iMin2 = Math.min(iMin2, point.y);
            iMax2 = Math.max(iMax2, point.y);
        }
        return new Rect(iMin, iMin2, iMax, iMax2);
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public String e() {
        return ((zzyb) this.b).c;
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public int f() {
        return ((zzyb) this.b).f;
    }

    @Override // androidx.compose.ui.text.input.s
    public int g(int i) {
        C0591b1 c0591b1 = (C0591b1) this.b;
        if (i <= c0591b1.a - 1) {
            return i;
        }
        if (i <= c0591b1.b - 1) {
            return i - 1;
        }
        int i2 = c0591b1.c;
        return i <= i2 + 1 ? i - 2 : i2;
    }

    @Override // org.chromium.support_lib_boundary.FeatureFlagHolderBoundaryInterface
    public String[] getSupportedFeatures() {
        return new String[]{"WEB_MESSAGE_LISTENER", "WEB_MESSAGE_ARRAY_BUFFER"};
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.b
    public void h(Bundle bundle, String str) {
        com.google.firebase.crashlytics.internal.common.p pVar = (com.google.firebase.crashlytics.internal.common.p) this.b;
        if (pVar != null) {
            try {
                String str2 = "$A$:" + v(bundle, str);
                com.google.firebase.crashlytics.internal.common.q qVar = pVar.a;
                qVar.getClass();
                qVar.o.a.a(new com.google.firebase.crashlytics.internal.common.o(qVar, System.currentTimeMillis() - qVar.d, str2, 0));
            } catch (JSONException unused) {
                Log.w("FirebaseCrashlytics", "Unable to serialize Firebase Analytics event to breadcrumb.", null);
            }
        }
    }

    public boolean i(C0219q c0219q, androidx.compose.ui.layout.r rVar, C3083y1 c3083y1, boolean z) {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
        int i = bVar.c;
        if (i <= 0) {
            return false;
        }
        Object[] objArr = bVar.a;
        int i2 = 0;
        boolean z2 = false;
        do {
            z2 = ((androidx.compose.ui.input.pointer.e) objArr[i2]).i(c0219q, rVar, c3083y1, z) || z2;
            i2++;
        } while (i2 < i);
        return z2;
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public Point[] j() {
        return ((zzyb) this.b).e;
    }

    @Override // com.google.firebase.crashlytics.internal.breadcrumbs.a
    public void k(com.google.firebase.crashlytics.internal.common.p pVar) {
        this.b = pVar;
        Log.isLoggable("FirebaseCrashlytics", 3);
    }

    public void l(C3083y1 c3083y1) {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
        int i = bVar.c;
        while (true) {
            i--;
            if (-1 >= i) {
                return;
            }
            if (((androidx.compose.ui.input.pointer.e) bVar.a[i]).d.a == 0) {
                bVar.o(i);
            }
        }
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public int m() {
        return ((zzyb) this.b).a;
    }

    public String n(Object obj) {
        StringWriter stringWriter = new StringWriter();
        try {
            com.google.firebase.encoders.json.d dVar = (com.google.firebase.encoders.json.d) this.b;
            com.google.firebase.encoders.json.e eVar = new com.google.firebase.encoders.json.e(stringWriter, dVar.a, dVar.b, dVar.c, dVar.d);
            eVar.h(obj);
            eVar.j();
            eVar.b.flush();
        } catch (IOException unused) {
        }
        return stringWriter.toString();
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public short o() throws IOException {
        int i = ((InputStream) this.b).read();
        if (i != -1) {
            return (short) i;
        }
        throw new DefaultImageHeaderParser$Reader$EndOfFileException();
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        ((CountDownLatch) this.b).countDown();
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:21:? A[RETURN, SYNTHETIC] */
    @Override // org.chromium.support_lib_boundary.WebMessageListenerBoundaryInterface
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onPostMessage(android.webkit.WebView r8, java.lang.reflect.InvocationHandler r9, android.net.Uri r10, boolean r11, java.lang.reflect.InvocationHandler r12) {
        /*
            r7 = this;
            java.lang.Class<org.chromium.support_lib_boundary.WebMessageBoundaryInterface> r0 = org.chromium.support_lib_boundary.WebMessageBoundaryInterface.class
            java.lang.Object r9 = org.chromium.support_lib_boundary.util.a.f(r0, r9)
            org.chromium.support_lib_boundary.WebMessageBoundaryInterface r9 = (org.chromium.support_lib_boundary.WebMessageBoundaryInterface) r9
            java.lang.reflect.InvocationHandler[] r0 = r9.getPorts()
            int r1 = r0.length
            com.google.firebase.platforminfo.c[] r1 = new com.google.firebase.platforminfo.c[r1]
            r2 = 0
        L10:
            int r3 = r0.length
            if (r2 >= r3) goto L29
            com.google.firebase.platforminfo.c r3 = new com.google.firebase.platforminfo.c
            r4 = r0[r2]
            r3.<init>()
            java.lang.Class<org.chromium.support_lib_boundary.WebMessagePortBoundaryInterface> r5 = org.chromium.support_lib_boundary.WebMessagePortBoundaryInterface.class
            java.lang.Object r4 = org.chromium.support_lib_boundary.util.a.f(r5, r4)
            org.chromium.support_lib_boundary.WebMessagePortBoundaryInterface r4 = (org.chromium.support_lib_boundary.WebMessagePortBoundaryInterface) r4
            r3.a = r4
            r1[r2] = r3
            int r2 = r2 + 1
            goto L10
        L29:
            androidx.webkit.internal.b r0 = androidx.webkit.internal.s.a
            boolean r0 = r0.b()
            if (r0 == 0) goto L5e
            java.lang.Class<org.chromium.support_lib_boundary.WebMessagePayloadBoundaryInterface> r0 = org.chromium.support_lib_boundary.WebMessagePayloadBoundaryInterface.class
            java.lang.reflect.InvocationHandler r9 = r9.getMessagePayload()
            java.lang.Object r9 = org.chromium.support_lib_boundary.util.a.f(r0, r9)
            org.chromium.support_lib_boundary.WebMessagePayloadBoundaryInterface r9 = (org.chromium.support_lib_boundary.WebMessagePayloadBoundaryInterface) r9
            int r0 = r9.getType()
            if (r0 == 0) goto L54
            r1 = 1
            if (r0 == r1) goto L49
            r9 = 0
            r3 = r9
            goto L68
        L49:
            androidx.webkit.d r0 = new androidx.webkit.d
            byte[] r9 = r9.getAsArrayBuffer()
            r0.<init>(r9)
        L52:
            r3 = r0
            goto L68
        L54:
            androidx.webkit.d r0 = new androidx.webkit.d
            java.lang.String r9 = r9.getAsString()
            r0.<init>(r9)
            goto L52
        L5e:
            androidx.webkit.d r0 = new androidx.webkit.d
            java.lang.String r9 = r9.getData()
            r0.<init>(r9)
            goto L52
        L68:
            if (r3 == 0) goto L8a
            java.lang.Class<org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface> r9 = org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface.class
            java.lang.Object r9 = org.chromium.support_lib_boundary.util.a.f(r9, r12)
            org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface r9 = (org.chromium.support_lib_boundary.JsReplyProxyBoundaryInterface) r9
            androidx.camera.core.impl.utils.executor.c r12 = new androidx.camera.core.impl.utils.executor.c
            r0 = 2
            r12.<init>(r9, r0)
            java.lang.Object r9 = r9.getOrCreatePeer(r12)
            r6 = r9
            androidx.webkit.internal.m r6 = (androidx.webkit.internal.m) r6
            java.lang.Object r9 = r7.b
            r1 = r9
            androidx.webkit.h r1 = (androidx.webkit.h) r1
            r2 = r8
            r4 = r10
            r5 = r11
            r1.onPostMessage(r2, r3, r4, r5, r6)
        L8a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.webkit.internal.p.onPostMessage(android.webkit.WebView, java.lang.reflect.InvocationHandler, android.net.Uri, boolean, java.lang.reflect.InvocationHandler):void");
    }

    @Override // androidx.compose.ui.text.input.s
    public int p(int i) {
        C0591b1 c0591b1 = (C0591b1) this.b;
        if (i < c0591b1.a) {
            return i;
        }
        if (i < c0591b1.b) {
            return i + 1;
        }
        int i2 = c0591b1.c;
        return i <= i2 ? i + 2 : i2 + 2;
    }

    public l0 q() {
        return (l0) ((s0) this.b).getValue();
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public int s(int i, byte[] bArr) throws DefaultImageHeaderParser$Reader$EndOfFileException {
        int i2 = 0;
        int i3 = 0;
        while (i2 < i && (i3 = ((InputStream) this.b).read(bArr, i2, i - i2)) != -1) {
            i2 += i3;
        }
        if (i2 == 0 && i3 == -1) {
            throw new DefaultImageHeaderParser$Reader$EndOfFileException();
        }
        return i2;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.k
    public long skip(long j) throws IOException {
        if (j < 0) {
            return 0L;
        }
        long j2 = j;
        while (j2 > 0) {
            InputStream inputStream = (InputStream) this.b;
            long jSkip = inputStream.skip(j2);
            if (jSkip > 0) {
                j2 -= jSkip;
            } else {
                if (inputStream.read() == -1) {
                    break;
                }
                j2--;
            }
        }
        return j - j2;
    }

    public void t(Activity activity) {
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) this.b;
        ArrayList arrayList = (ArrayList) kVar.d;
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            WeakReference weakReference = (WeakReference) it2.next();
            if (weakReference.get() == activity) {
                arrayList.remove(weakReference);
                break;
            }
        }
        activity.getWindow().removeOnFrameMetricsAvailableListener((WindowOnFrameMetricsAvailableListenerC1022i) kVar.e);
    }

    public String toString() {
        switch (this.a) {
            case 19:
                StringBuilder sb = new StringBuilder("1");
                for (EnumC3879l0 enumC3879l0 : EnumC3879l0.values()) {
                    EnumC3866f enumC3866f = (EnumC3866f) ((EnumMap) this.b).get(enumC3879l0);
                    if (enumC3866f == null) {
                        enumC3866f = EnumC3866f.b;
                    }
                    sb.append(enumC3866f.a);
                }
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public void u() {
        int i = 0;
        while (true) {
            androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.b;
            if (i >= bVar.c) {
                return;
            }
            androidx.compose.ui.input.pointer.e eVar = (androidx.compose.ui.input.pointer.e) bVar.a[i];
            if (eVar.c.m) {
                i++;
                eVar.u();
            } else {
                eVar.A();
                bVar.o(i);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0029  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void w(androidx.datastore.core.l0 r6) {
        /*
            r5 = this;
            java.lang.String r0 = "newState"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
        L5:
            java.lang.Object r0 = r5.b
            kotlinx.coroutines.flow.s0 r0 = (kotlinx.coroutines.flow.s0) r0
            java.lang.Object r1 = r0.getValue()
            r2 = r1
            androidx.datastore.core.l0 r2 = (androidx.datastore.core.l0) r2
            boolean r3 = r2 instanceof androidx.datastore.core.c0
            if (r3 == 0) goto L16
            r3 = 1
            goto L1c
        L16:
            androidx.datastore.core.o0 r3 = androidx.datastore.core.o0.b
            boolean r3 = kotlin.jvm.internal.Intrinsics.b(r2, r3)
        L1c:
            if (r3 == 0) goto L1f
            goto L29
        L1f:
            boolean r3 = r2 instanceof androidx.datastore.core.C1071c
            if (r3 == 0) goto L2b
            int r3 = r6.a
            int r4 = r2.a
            if (r3 <= r4) goto L2f
        L29:
            r2 = r6
            goto L2f
        L2b:
            boolean r3 = r2 instanceof androidx.datastore.core.a0
            if (r3 == 0) goto L36
        L2f:
            boolean r0 = r0.k(r1, r2)
            if (r0 == 0) goto L5
            return
        L36:
            kotlin.NoWhenBranchMatchedException r6 = new kotlin.NoWhenBranchMatchedException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.webkit.internal.p.w(androidx.datastore.core.l0):void");
    }

    public void x(C1939ct c1939ct) {
        p0 p0Var = (p0) this.b;
        p0Var.getClass();
        String str = c1939ct.b;
        if (!TextUtils.isEmpty(str)) {
            if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.xb)).booleanValue()) {
                p0Var.c = str;
            }
        }
        int i = c1939ct.a;
        switch (i) {
            case 8152:
                p0Var.p(new HashMap(), "onLMDOverlayOpened");
                break;
            case 8153:
                p0Var.p(new HashMap(), "onLMDOverlayClicked");
                break;
            case 8155:
                p0Var.p(new HashMap(), "onLMDOverlayClose");
                break;
            case 8157:
                p0Var.c = null;
                p0Var.d = null;
                p0Var.b = false;
                break;
            case 8160:
            case 8161:
            case 8162:
                HashMap map = new HashMap();
                map.put("error", String.valueOf(i));
                p0Var.p(map, "onLMDOverlayFailedToOpen");
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void y(com.google.android.gms.measurement.internal.EnumC3879l0 r3, int r4) {
        /*
            r2 = this;
            com.google.android.gms.measurement.internal.f r0 = com.google.android.gms.measurement.internal.EnumC3866f.b
            r1 = -30
            if (r4 == r1) goto L1e
            r1 = -20
            if (r4 == r1) goto L1b
            r1 = -10
            if (r4 == r1) goto L18
            if (r4 == 0) goto L1b
            r1 = 30
            if (r4 == r1) goto L15
            goto L20
        L15:
            com.google.android.gms.measurement.internal.f r0 = com.google.android.gms.measurement.internal.EnumC3866f.f
            goto L20
        L18:
            com.google.android.gms.measurement.internal.f r0 = com.google.android.gms.measurement.internal.EnumC3866f.e
            goto L20
        L1b:
            com.google.android.gms.measurement.internal.f r0 = com.google.android.gms.measurement.internal.EnumC3866f.g
            goto L20
        L1e:
            com.google.android.gms.measurement.internal.f r0 = com.google.android.gms.measurement.internal.EnumC3866f.h
        L20:
            java.lang.Object r4 = r2.b
            java.util.EnumMap r4 = (java.util.EnumMap) r4
            r4.put(r3, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.webkit.internal.p.y(com.google.android.gms.measurement.internal.l0, int):void");
    }

    public void z(EnumC3879l0 enumC3879l0, EnumC3866f enumC3866f) {
        ((EnumMap) this.b).put((EnumMap) enumC3879l0, (EnumC3879l0) enumC3866f);
    }

    public /* synthetic */ p(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public p(EnumMap enumMap) {
        this.a = 19;
        EnumMap enumMap2 = new EnumMap(EnumC3879l0.class);
        this.b = enumMap2;
        enumMap2.putAll(enumMap);
    }

    public p(com.quizlet.billing.model.a billingInventory) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(billingInventory, "billingInventory");
        this.b = billingInventory;
    }

    public p(com.quizlet.usecase.a onUserChange) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(onUserChange, "onUserChange");
        this.b = onUserChange;
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0029 A[PHI: r11
  0x0029: PHI (r11v1 int) = (r11v0 int), (r11v4 int), (r11v5 int) binds: [B:5:0x0019, B:10:0x0022, B:12:0x0025] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0032  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p(int[] r22, float[] r23, float[][] r24) {
        /*
            r21 = this;
            r0 = r21
            r1 = r23
            r2 = 3
            r0.a = r2
            r0.<init>()
            int r2 = r1.length
            r3 = 1
            int r2 = r2 - r3
            androidx.compose.animation.core.v[][] r4 = new androidx.compose.animation.core.C0271v[r2][]
            r5 = 0
            r7 = r3
            r8 = r7
            r6 = r5
        L13:
            if (r6 >= r2) goto L72
            r9 = r22[r6]
            r10 = 2
            r11 = 3
            if (r9 == 0) goto L29
            if (r9 == r3) goto L32
            if (r9 == r10) goto L30
            if (r9 == r11) goto L2b
            r11 = 4
            if (r9 == r11) goto L29
            r11 = 5
            if (r9 == r11) goto L29
            r12 = r8
            goto L34
        L29:
            r12 = r11
            goto L34
        L2b:
            if (r7 != r3) goto L32
            goto L30
        L2e:
            r12 = r7
            goto L34
        L30:
            r7 = r10
            goto L2e
        L32:
            r7 = r3
            goto L2e
        L34:
            r8 = r24[r6]
            int r9 = r8.length
            int r9 = r9 / r10
            int r8 = r8.length
            int r8 = r8 % r10
            int r8 = r8 + r9
            androidx.compose.animation.core.v[] r9 = new androidx.compose.animation.core.C0271v[r8]
            r10 = r5
        L3e:
            if (r10 >= r8) goto L6c
            int r11 = r10 * 2
            r13 = r11
            androidx.compose.animation.core.v r11 = new androidx.compose.animation.core.v
            r14 = r13
            r13 = r1[r6]
            int r15 = r6 + 1
            r16 = r14
            r14 = r1[r15]
            r17 = r24[r6]
            r18 = r15
            r15 = r17[r16]
            int r19 = r16 + 1
            r17 = r17[r19]
            r18 = r24[r18]
            r16 = r18[r16]
            r18 = r18[r19]
            r20 = r17
            r17 = r16
            r16 = r20
            r11.<init>(r12, r13, r14, r15, r16, r17, r18)
            r9[r10] = r11
            int r10 = r10 + 1
            goto L3e
        L6c:
            r4[r6] = r9
            int r6 = r6 + 1
            r8 = r12
            goto L13
        L72:
            r0.b = r4
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.webkit.internal.p.<init>(int[], float[], float[][]):void");
    }

    public p(int i) {
        this.a = i;
        switch (i) {
            case 6:
                this.b = new androidx.compose.runtime.collection.b(new androidx.compose.ui.input.pointer.e[16]);
                break;
            case 7:
                this.b = new com.google.android.gms.cloudmessaging.k(2);
                break;
            case 9:
                this.b = e0.c(o0.b);
                break;
            case 19:
                this.b = new EnumMap(EnumC3879l0.class);
                break;
            case 27:
                this.b = new androidx.navigation.internal.m();
                break;
            default:
                this.b = (ExtraSupportedSurfaceCombinationsQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ExtraSupportedSurfaceCombinationsQuirk.class);
                break;
        }
    }

    public p(TextView textView) {
        this.a = 10;
        this.b = new androidx.emoji2.viewsintegration.f(textView);
    }
}
