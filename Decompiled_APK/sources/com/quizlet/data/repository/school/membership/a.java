package com.quizlet.data.repository.school.membership;

import android.graphics.Typeface;
import android.media.Image;
import android.os.Build;
import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowInsetsController;
import android.webkit.WebView;
import androidx.appcompat.app.L;
import androidx.appcompat.view.menu.l;
import androidx.appcompat.view.menu.n;
import androidx.appcompat.widget.C0095l;
import androidx.appcompat.widget.C0122z;
import androidx.appcompat.widget.Toolbar;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.compat.quirk.SmallDisplaySizeQuirk;
import androidx.camera.core.impl.utils.executor.k;
import androidx.camera.core.impl.utils.futures.c;
import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.foundation.gestures.G0;
import androidx.compose.foundation.gestures.snapping.b;
import androidx.compose.foundation.lazy.grid.m;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.InterfaceC0530k;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.foundation.text.selection.r;
import androidx.compose.ui.focus.p;
import androidx.compose.ui.text.input.A;
import androidx.core.view.B;
import androidx.core.view.InterfaceC1058o;
import androidx.core.view.InterfaceC1062t;
import androidx.datastore.core.f0;
import androidx.fragment.app.W;
import androidx.profileinstaller.ProfileInstallReceiver;
import androidx.webkit.internal.v;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.android.installreferrer.api.InstallReferrerClient;
import com.android.installreferrer.api.InstallReferrerStateListener;
import com.android.installreferrer.api.ReferrerDetails;
import com.bumptech.glide.load.h;
import com.facebook.appevents.j;
import com.facebook.o;
import com.google.android.gms.analytics.f;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3282v5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.google.android.gms.internal.mlkit_vision_barcode.I7;
import com.google.android.gms.internal.mlkit_vision_barcode.J5;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3602d5;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.w1;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.d;
import com.google.firebase.crashlytics.internal.common.i;
import com.google.firebase.heartbeatinfo.e;
import com.google.mlkit.vision.documentscanner.internal.GmsDocumentScanningDelegateActivity;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.generated.enums.H;
import com.quizlet.generated.enums.J;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.functions.g;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.chromium.support_lib_boundary.StaticsBoundaryInterface;
import org.chromium.support_lib_boundary.WebViewProviderBoundaryInterface;
import org.chromium.support_lib_boundary.WebViewProviderFactoryBoundaryInterface;
import org.chromium.support_lib_boundary.WebkitToCompatConverterBoundaryInterface;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;
import retrofit2.K;

/* loaded from: classes2.dex */
public final class a implements l, c, b, InterfaceC0530k, androidx.profileinstaller.c, v, com.bumptech.glide.load.b, InstallReferrerStateListener, com.google.android.gms.tasks.a, w1, d, com.google.android.gms.tasks.c, com.google.android.gms.tasks.b, InterfaceC1062t, com.google.android.material.resources.a, I7, InterfaceC5182g, g {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.compose.foundation.gestures.snapping.b
    public Object B(G0 g0, Float f, Float f2, androidx.compose.foundation.gestures.snapping.d dVar, androidx.compose.foundation.gestures.snapping.g gVar) {
        float fFloatValue = f.floatValue();
        float fFloatValue2 = f2.floatValue();
        Object objB = androidx.compose.foundation.gestures.snapping.l.b(g0, Math.signum(fFloatValue2) * Math.abs(fFloatValue), fFloatValue, AbstractC0240f.b(DefinitionKt.NO_Float_VALUE, fFloatValue2, 28), (C0253l0) this.b, dVar, gVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : (androidx.compose.foundation.gestures.snapping.a) objB;
    }

    @Override // androidx.appcompat.view.menu.l
    public void D(n nVar) {
        Toolbar toolbar = (Toolbar) this.b;
        C0095l c0095l = toolbar.a.t;
        if (c0095l == null || !c0095l.i()) {
            Iterator it2 = toolbar.G.b.iterator();
            while (it2.hasNext()) {
                ((W) ((InterfaceC1058o) it2.next())).a.u(nVar);
            }
        }
        L l = toolbar.W;
        if (l != null) {
            l.D(nVar);
        }
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public boolean a(long j, r rVar) {
        C0492h0 c0492h0;
        i0 i0Var = (i0) this.b;
        if (!i0Var.j() || i0Var.l().a.a.length() == 0 || (c0492h0 = i0Var.d) == null || c0492h0.d() == null) {
            return false;
        }
        p pVar = i0Var.j;
        if (pVar != null) {
            pVar.b();
        }
        i0Var.m = j;
        i0Var.r = -1;
        i0Var.h(true);
        s(i0Var.l(), i0Var.m, true, rVar);
        return true;
    }

    @Override // androidx.profileinstaller.c
    public void b(int i, Serializable serializable) {
        String str;
        switch (i) {
            case 1:
                str = "RESULT_INSTALL_SUCCESS";
                break;
            case 2:
                str = "RESULT_ALREADY_INSTALLED";
                break;
            case 3:
                str = "RESULT_UNSUPPORTED_ART_VERSION";
                break;
            case 4:
                str = "RESULT_NOT_WRITABLE";
                break;
            case 5:
                str = "RESULT_DESIRED_FORMAT_UNSUPPORTED";
                break;
            case 6:
                str = "RESULT_BASELINE_PROFILE_NOT_FOUND";
                break;
            case 7:
                str = "RESULT_IO_EXCEPTION";
                break;
            case 8:
                str = "RESULT_PARSE_EXCEPTION";
                break;
            case 9:
            default:
                str = "";
                break;
            case 10:
                str = "RESULT_INSTALL_SKIP_FILE_SUCCESS";
                break;
            case 11:
                str = "RESULT_DELETE_SKIP_FILE_SUCCESS";
                break;
        }
        if (i == 6 || i == 7 || i == 8) {
            Log.e("ProfileInstaller", str, (Throwable) serializable);
        }
        ((ProfileInstallReceiver) this.b).setResultCode(i);
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public boolean c(long j, r rVar) {
        C0492h0 c0492h0;
        i0 i0Var = (i0) this.b;
        if (!i0Var.j() || i0Var.l().a.a.length() == 0 || (c0492h0 = i0Var.d) == null || c0492h0.d() == null) {
            return false;
        }
        s(i0Var.l(), j, false, rVar);
        return true;
    }

    @Override // androidx.webkit.internal.v
    public WebViewProviderBoundaryInterface createWebView(WebView webView) {
        return (WebViewProviderBoundaryInterface) org.chromium.support_lib_boundary.util.a.f(WebViewProviderBoundaryInterface.class, ((WebViewProviderFactoryBoundaryInterface) this.b).createWebView(webView));
    }

    @Override // androidx.webkit.internal.v
    public String[] d() {
        return ((WebViewProviderFactoryBoundaryInterface) this.b).getSupportedFeatures();
    }

    @Override // io.reactivex.rxjava3.functions.g
    public Object e(Object obj, Object obj2, Object obj3, Object obj4, Object obj5) {
        String str;
        String str2;
        String strA;
        String strB;
        Integer age = (Integer) obj;
        Integer isTeacher = (Integer) obj2;
        Boolean isLoggedOutUser = (Boolean) obj3;
        Boolean isFreeUser = (Boolean) obj4;
        Boolean isPrebidEnabled = (Boolean) obj5;
        Intrinsics.checkNotNullParameter(age, "age");
        Intrinsics.checkNotNullParameter(isTeacher, "isTeacher");
        Intrinsics.checkNotNullParameter(isLoggedOutUser, "isLoggedOutUser");
        Intrinsics.checkNotNullParameter(isFreeUser, "isFreeUser");
        Intrinsics.checkNotNullParameter(isPrebidEnabled, "isPrebidEnabled");
        Pair pair = new Pair("a", String.valueOf(age.intValue()));
        int iIntValue = age.intValue();
        com.quizlet.ads.b bVar = (com.quizlet.ads.b) this.b;
        bVar.getClass();
        Pair pair2 = new Pair("g", String.valueOf(iIntValue < 13 ? 0 : iIntValue < 18 ? 1 : iIntValue < 25 ? 2 : iIntValue < 35 ? 3 : iIntValue < 45 ? 4 : iIntValue < 55 ? 5 : iIntValue < 65 ? 6 : 7));
        Pair pair3 = new Pair("t", String.valueOf(isTeacher.intValue()));
        Pair pair4 = new Pair("l", isLoggedOutUser.booleanValue() ? "0" : "1");
        if (isFreeUser.booleanValue()) {
            str = "1";
            str2 = "0";
        } else {
            str = "0";
            str2 = str;
        }
        Pair pair5 = new Pair("e", str);
        com.quizlet.ads.d dVar = bVar.b;
        Pair pair6 = new Pair("f", dVar.b.getInt(String.valueOf(dVar.a), 0) != 1 ? str2 : "1");
        androidx.work.impl.model.c cVar = bVar.a;
        J jK = cVar.k();
        if (CollectionsKt.F(com.quizlet.ads.b.d, jK)) {
            H hG = cVar.g();
            String upperCase = null;
            String strA2 = jK != null ? jK.a() : null;
            if (hG != null && (strB = hG.b()) != null) {
                upperCase = strB.toUpperCase(Locale.ROOT);
                Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
            }
            strA = android.support.v4.media.session.a.l(strA2, "-", upperCase);
        } else if (jK == null || (strA = jK.a()) == null) {
            strA = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
        }
        return V.f(pair, pair2, pair3, pair4, pair5, pair6, new Pair("n", strA), new Pair("exp_nativesdk", isPrebidEnabled.booleanValue() ? "experiment" : "control"));
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        OTLogger.c("TV Vendor", 6, "IAB Vendor Disclosure API Failed :  " + th.getMessage());
    }

    @Override // com.google.android.gms.measurement.internal.w1
    public void g(String str, String str2, Bundle bundle) {
        boolean zIsEmpty = TextUtils.isEmpty(str);
        D0 d0 = (D0) this.b;
        if (!zIsEmpty) {
            d0.getClass();
            throw new IllegalStateException("Unexpected call on client side");
        }
        ((Y) d0.b).n.getClass();
        d0.b0("auto", "_err", bundle, true, true, System.currentTimeMillis());
    }

    @Override // androidx.webkit.internal.v
    public StaticsBoundaryInterface getStatics() {
        return (StaticsBoundaryInterface) org.chromium.support_lib_boundary.util.a.f(StaticsBoundaryInterface.class, ((WebViewProviderFactoryBoundaryInterface) this.b).getStatics());
    }

    @Override // androidx.webkit.internal.v
    public WebkitToCompatConverterBoundaryInterface getWebkitToCompatConverter() {
        return (WebkitToCompatConverterBoundaryInterface) org.chromium.support_lib_boundary.util.a.f(WebkitToCompatConverterBoundaryInterface.class, ((WebViewProviderFactoryBoundaryInterface) this.b).getWebkitToCompatConverter());
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        if (task.l() || task.j()) {
            return task;
        }
        Exception excG = task.g();
        if (!(excG instanceof ApiException)) {
            return task;
        }
        int i = ((ApiException) excG).a.a;
        return (i == 43001 || i == 43002 || i == 43003 || i == 17) ? ((com.google.android.gms.internal.appset.g) this.b).b.b() : i == 43000 ? S3.h(new Exception("Failed to get app set ID due to an internal error. Please try again later.")) : i != 15 ? task : S3.h(new Exception("The operation to get app set ID timed out. Please try again later."));
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0530k
    public void i() {
    }

    @Override // com.google.android.gms.tasks.b
    public void j() {
        ((CountDownLatch) this.b).countDown();
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, K k) {
        OTLogger.c("TV Vendor", 4, "IAB Vendor Disclosure API Success");
        new Thread(new i(10, this, k)).start();
    }

    @Override // com.google.android.material.resources.a
    public void l(Typeface typeface) {
        com.google.android.material.internal.b bVar = (com.google.android.material.internal.b) this.b;
        if (bVar.m(typeface)) {
            bVar.i(false);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v0 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v2, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v5 */
    /* JADX WARN: Type inference failed for: r2v7 */
    /* JADX WARN: Type inference failed for: r2v9 */
    @Override // com.bumptech.glide.load.b
    public boolean m(Object obj, File file, h hVar) throws Throwable {
        InputStream inputStream = (InputStream) obj;
        m mVar = (m) this.b;
        byte[] bArr = (byte[]) mVar.f(65536, byte[].class);
        boolean z = false;
        ?? r2 = 0;
        FileOutputStream fileOutputStream = null;
        try {
            try {
                FileOutputStream fileOutputStream2 = new FileOutputStream(file);
                while (true) {
                    try {
                        int i = inputStream.read(bArr);
                        r2 = -1;
                        if (i == -1) {
                            break;
                        }
                        fileOutputStream2.write(bArr, 0, i);
                    } catch (IOException unused) {
                        fileOutputStream = fileOutputStream2;
                        Log.isLoggable("StreamEncoder", 3);
                        if (fileOutputStream != null) {
                            try {
                                fileOutputStream.close();
                            } catch (IOException unused2) {
                            }
                        }
                        mVar.k(bArr);
                        r2 = fileOutputStream;
                        return z;
                    } catch (Throwable th) {
                        th = th;
                        r2 = fileOutputStream2;
                        if (r2 != 0) {
                            try {
                                r2.close();
                            } catch (IOException unused3) {
                            }
                        }
                        mVar.k(bArr);
                        throw th;
                    }
                }
                fileOutputStream2.close();
                try {
                    fileOutputStream2.close();
                } catch (IOException unused4) {
                }
                mVar.k(bArr);
                z = true;
            } catch (Throwable th2) {
                th = th2;
            }
        } catch (IOException unused5) {
        }
        return z;
    }

    public ByteBuffer o() {
        return ((Image.Plane) this.b).getBuffer();
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        boolean z = th instanceof TimeoutException;
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.b;
        if (z) {
            iVar.d(th);
        } else {
            iVar.b(Collections.EMPTY_LIST);
        }
    }

    @Override // com.android.installreferrer.api.InstallReferrerStateListener
    public void onInstallReferrerServiceDisconnected() {
    }

    @Override // com.android.installreferrer.api.InstallReferrerStateListener
    public void onInstallReferrerSetupFinished(int i) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        InstallReferrerClient installReferrerClient = (InstallReferrerClient) this.b;
        try {
            if (i == 0) {
                try {
                    ReferrerDetails installReferrer = installReferrerClient.getInstallReferrer();
                    Intrinsics.checkNotNullExpressionValue(installReferrer, "{\n                      …rer\n                    }");
                    String installReferrer2 = installReferrer.getInstallReferrer();
                    if (installReferrer2 != null && (StringsKt.G(installReferrer2, "fb", false) || StringsKt.G(installReferrer2, "facebook", false))) {
                        String str = j.c;
                        o.a().getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).edit().putString("install_referrer", installReferrer2).apply();
                    }
                    o.a().getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).edit().putBoolean("is_referrer_updated", true).apply();
                } catch (RemoteException | Exception unused) {
                    return;
                }
            } else if (i == 2) {
                o.a().getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).edit().putBoolean("is_referrer_updated", true).apply();
            }
            installReferrerClient.endConnection();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        switch (this.a) {
            case 6:
                List list = (List) obj;
                list.getClass();
                ((androidx.concurrent.futures.i) this.b).b(new ArrayList(list));
                break;
            default:
                ((CountDownLatch) this.b).countDown();
                break;
        }
    }

    public int p() {
        return ((Image.Plane) this.b).getPixelStride();
    }

    public int q() {
        return ((Image.Plane) this.b).getRowStride();
    }

    @Override // androidx.appcompat.view.menu.l
    public boolean r(n nVar, MenuItem menuItem) {
        L l = ((Toolbar) this.b).W;
        return false;
    }

    public void s(A a, long j, boolean z, r rVar) {
        ((i0) this.b).p(androidx.compose.ui.text.K.b(i0.c((i0) this.b, a, j, z, false, rVar, false)) ? androidx.compose.foundation.text.V.c : androidx.compose.foundation.text.V.b);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        switch (this.a) {
            case 21:
                ((CountDownLatch) this.b).countDown();
                break;
            default:
                GmsDocumentScanningDelegateActivity gmsDocumentScanningDelegateActivity = (GmsDocumentScanningDelegateActivity) this.b;
                if (Log.isLoggable("GmsDocScanDelAct", 6)) {
                    Log.e("GmsDocScanDelAct", "Failed to handle scanning result", exc);
                }
                gmsDocumentScanningDelegateActivity.setResult(0);
                gmsDocumentScanningDelegateActivity.q(EnumC3602d5.CANCELLED, 0);
                gmsDocumentScanningDelegateActivity.finish();
                break;
        }
    }

    public String toString() {
        switch (this.a) {
            case 17:
                HashMap map = new HashMap();
                for (Map.Entry entry : ((HashMap) this.b).entrySet()) {
                    if (((String) entry.getKey()).startsWith("&")) {
                        map.put(((String) entry.getKey()).substring(1), (String) entry.getValue());
                    } else {
                        map.put((String) entry.getKey(), (String) entry.getValue());
                    }
                }
                return f.zzb(map);
            default:
                return super.toString();
        }
    }

    public void u(String str, String str2) {
        ((HashMap) this.b).put(str, str2);
    }

    @Override // androidx.core.view.InterfaceC1062t
    public androidx.core.view.D0 w(androidx.core.view.D0 d0, View view) {
        com.google.android.material.bottomsheet.h hVar = (com.google.android.material.bottomsheet.h) this.b;
        com.google.android.material.bottomsheet.g gVar = hVar.m;
        if (gVar != null) {
            hVar.f.g1.remove(gVar);
        }
        com.google.android.material.bottomsheet.g gVar2 = new com.google.android.material.bottomsheet.g(d0, hVar.i);
        hVar.m = gVar2;
        gVar2.e(hVar.getWindow());
        hVar.f.w(hVar.m);
        return d0;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.I7
    public C0122z zza() {
        c0 c0Var = new c0(9, false);
        c0Var.d = com.google.mlkit.vision.barcode.internal.a.c() ? EnumC3282v5.TYPE_THICK : EnumC3282v5.TYPE_THIN;
        L l = new L(22);
        l.b = (EnumC3290w5) this.b;
        c0Var.f = new J5(l);
        return new C0122z(c0Var, 0);
    }

    public a(String str) {
        this.a = 17;
        this.b = new HashMap();
        u("&pa", str);
    }

    public a(com.quizlet.remote.model.school.h remote) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(remote, "remote");
        this.b = remote;
    }

    public a(androidx.work.impl.r workManager) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(workManager, "workManager");
        this.b = workManager;
    }

    public a(k executor) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(executor, "executor");
        this.b = new AtomicInteger(0);
    }

    public a(InstallReferrerClient installReferrerClient, e eVar) {
        this.a = 16;
        this.b = installReferrerClient;
    }

    public a(int i) {
        this.a = i;
        switch (i) {
            case 19:
                break;
            case 20:
            default:
                this.b = (SmallDisplaySizeQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(SmallDisplaySizeQuirk.class);
                break;
            case 21:
                this.b = new CountDownLatch(1);
                break;
        }
    }

    public a(View view) {
        this.a = 10;
        if (Build.VERSION.SDK_INT >= 30) {
            B b = new B(view, 11);
            b.c = view;
            this.b = b;
            return;
        }
        this.b = new L(view, 11);
    }

    public a(WindowInsetsController windowInsetsController) {
        this.a = 10;
        B b = new B(null, 11);
        b.d = windowInsetsController;
        this.b = b;
    }

    public a(f0 delegate) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
    }
}
