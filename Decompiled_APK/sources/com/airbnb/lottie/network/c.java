package com.airbnb.lottie.network;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.graphics.Point;
import android.graphics.Rect;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Base64;
import android.util.JsonWriter;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.app.B;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.appcompat.view.menu.g;
import androidx.appcompat.view.menu.n;
import androidx.appcompat.view.menu.p;
import androidx.appcompat.widget.ActionBarContextView;
import androidx.appcompat.widget.B1;
import androidx.appcompat.widget.C1;
import androidx.appcompat.widget.H0;
import androidx.camera.camera2.internal.compat.quirk.CaptureSessionOnClosedNotCalledQuirk;
import androidx.camera.core.O;
import androidx.camera.core.impl.i0;
import androidx.collection.C0219q;
import androidx.compose.ui.platform.C0971v;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.M;
import androidx.core.view.V;
import androidx.datastore.core.CorruptionException;
import androidx.datastore.core.InterfaceC1070b;
import androidx.work.impl.o;
import com.amazon.device.ads.DtbConstants;
import com.bumptech.glide.load.f;
import com.google.android.gms.ads.internal.util.client.e;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.common.api.internal.i;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_barcode.zzu;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3538u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3544v;
import com.google.android.gms.internal.p000authapi.h;
import com.google.android.gms.internal.p000authapi.m;
import com.google.android.gms.measurement.internal.C3881m0;
import com.google.android.gms.measurement.internal.EnumC3875j0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.gms.measurement.internal.w1;
import com.quizlet.quizletandroid.R;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.WeakHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes.dex */
public class c implements InterfaceC1062t, H0, androidx.camera.core.impl.utils.futures.c, InterfaceC1070b, f, e, i, w1, com.google.android.material.chip.i, com.google.firebase.crashlytics.internal.analytics.a, com.google.mlkit.vision.barcode.common.internal.a, com.google.zxing.b {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ c(com.google.android.gms.internal.p000authapi.b bVar, BeginSignInRequest beginSignInRequest) {
        this.a = 21;
        this.b = beginSignInRequest;
    }

    public static c B(String str) {
        return new c((TextUtils.isEmpty(str) || str.length() > 1) ? EnumC3875j0.UNINITIALIZED : C3881m0.c(str.charAt(0)), 22);
    }

    public static String p(String str, b bVar, boolean z) throws NoSuchAlgorithmException {
        String strConcat = bVar.a;
        if (z) {
            strConcat = ".temp".concat(strConcat);
        }
        String strReplaceAll = str.replaceAll("\\W+", "");
        int length = 242 - strConcat.length();
        if (strReplaceAll.length() > length) {
            try {
                byte[] bArrDigest = MessageDigest.getInstance("MD5").digest(strReplaceAll.getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : bArrDigest) {
                    sb.append(String.format("%02x", Byte.valueOf(b)));
                }
                strReplaceAll = sb.toString();
            } catch (NoSuchAlgorithmException unused) {
                strReplaceAll = strReplaceAll.substring(0, length);
            }
        }
        return android.support.v4.media.session.a.B("lottie_cache_", strReplaceAll, strConcat);
    }

    public File A(String str, InputStream inputStream, b bVar) throws NoSuchAlgorithmException, IOException {
        File file = new File(x(), p(str, bVar, true));
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            try {
                byte[] bArr = new byte[1024];
                while (true) {
                    int i = inputStream.read(bArr);
                    if (i == -1) {
                        fileOutputStream.flush();
                        fileOutputStream.close();
                        return file;
                    }
                    fileOutputStream.write(bArr, 0, i);
                }
            } catch (Throwable th) {
                fileOutputStream.close();
                throw th;
            }
        } finally {
            inputStream.close();
        }
    }

    @Override // com.bumptech.glide.load.f
    public void a(byte[] bArr, Object obj, MessageDigest messageDigest) {
        Long l = (Long) obj;
        messageDigest.update(bArr);
        synchronized (((ByteBuffer) this.b)) {
            ((ByteBuffer) this.b).position(0);
            messageDigest.update(((ByteBuffer) this.b).putLong(l.longValue()).array());
        }
    }

    @Override // com.google.android.gms.common.api.internal.i
    public void accept(Object obj, Object obj2) {
        com.google.android.gms.internal.p000authapi.a aVar = new com.google.android.gms.internal.p000authapi.a((com.google.android.gms.tasks.f) obj2, 1);
        m mVar = (m) ((com.google.android.gms.internal.p000authapi.d) obj).m();
        BeginSignInRequest beginSignInRequest = (BeginSignInRequest) this.b;
        Parcel parcelX = mVar.X();
        int i = h.a;
        parcelX.writeStrongBinder(aVar);
        h.c(parcelX, beginSignInRequest);
        mVar.f0(1, parcelX);
    }

    @Override // androidx.datastore.core.InterfaceC1070b
    public Object b(CorruptionException corruptionException) {
        return ((Function1) this.b).invoke(corruptionException);
    }

    @Override // androidx.appcompat.widget.H0
    public void c(n nVar, p pVar) {
        androidx.appcompat.view.menu.h hVar = (androidx.appcompat.view.menu.h) this.b;
        hVar.f.removeCallbacksAndMessages(null);
        ArrayList arrayList = hVar.h;
        int size = arrayList.size();
        int i = 0;
        while (true) {
            if (i >= size) {
                i = -1;
                break;
            } else if (nVar == ((g) arrayList.get(i)).b) {
                break;
            } else {
                i++;
            }
        }
        if (i == -1) {
            return;
        }
        int i2 = i + 1;
        hVar.f.postAtTime(new RunnableC0069f(this, i2 < arrayList.size() ? (g) arrayList.get(i2) : null, pVar, nVar, 0), nVar, SystemClock.uptimeMillis() + 200);
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public Rect d() {
        zzu zzuVar = (zzu) this.b;
        if (zzuVar.e == null) {
            return null;
        }
        int i = 0;
        int iMax = Integer.MIN_VALUE;
        int iMin = Integer.MAX_VALUE;
        int iMin2 = Integer.MAX_VALUE;
        int iMax2 = Integer.MIN_VALUE;
        while (true) {
            Point[] pointArr = zzuVar.e;
            if (i >= pointArr.length) {
                return new Rect(iMin, iMin2, iMax, iMax2);
            }
            Point point = pointArr[i];
            iMin = Math.min(iMin, point.x);
            iMax = Math.max(iMax, point.x);
            iMin2 = Math.min(iMin2, point.y);
            iMax2 = Math.max(iMax2, point.y);
            i++;
        }
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public String e() {
        return ((zzu) this.b).b;
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public int f() {
        return ((zzu) this.b).d;
    }

    @Override // com.google.android.gms.measurement.internal.w1
    public void g(String str, String str2, Bundle bundle) {
        boolean zIsEmpty = TextUtils.isEmpty(str);
        r1 r1Var = (r1) this.b;
        if (!zIsEmpty) {
            r1Var.i().c0(new RunnableC0069f(this, str, str2, bundle, 22));
            return;
        }
        Y y = r1Var.l;
        if (y != null) {
            I i = y.i;
            Y.k(i);
            i.g.g("AppId not known when logging event", str2);
        }
    }

    public void h(int i, androidx.core.view.accessibility.e eVar, String str, Bundle bundle) {
    }

    @Override // com.google.android.gms.ads.internal.util.client.e
    public void i(JsonWriter jsonWriter) throws IOException {
        Object obj = com.google.android.gms.ads.internal.util.client.f.b;
        jsonWriter.name("params").beginObject();
        byte[] bArr = (byte[]) this.b;
        int length = bArr.length;
        String strEncodeToString = Base64.encodeToString(bArr, 0);
        if (length < 10000) {
            jsonWriter.name("body").value(strEncodeToString);
        } else {
            String strA = com.google.android.gms.ads.internal.util.client.c.a(strEncodeToString, "MD5");
            if (strA != null) {
                jsonWriter.name("bodydigest").value(strA);
            }
        }
        jsonWriter.name("bodylength").value(length);
        jsonWriter.endObject();
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public Point[] j() {
        return ((zzu) this.b).e;
    }

    public androidx.core.view.accessibility.e k(int i) {
        return null;
    }

    @Override // com.google.zxing.b
    public com.google.zxing.common.b l(String str, int i, int i2, int i3, EnumMap enumMap) {
        if (i != 15) {
            throw new IllegalArgumentException("Can only encode UPC-A, but got ".concat(Z.t(i)));
        }
        return ((com.google.zxing.oned.f) this.b).l("0".concat(String.valueOf(str)), 8, i2, i3, enumMap);
    }

    @Override // com.google.mlkit.vision.barcode.common.internal.a
    public int m() {
        return ((zzu) this.b).a;
    }

    @Override // com.google.firebase.crashlytics.internal.analytics.a
    public void n(Bundle bundle) {
        ((com.google.firebase.analytics.connector.c) ((com.google.firebase.analytics.connector.b) this.b)).a("clx", "_ae", bundle);
    }

    @Override // androidx.appcompat.widget.H0
    public void o(n nVar, p pVar) {
        ((androidx.appcompat.view.menu.h) this.b).f.removeCallbacksAndMessages(nVar);
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) throws Exception {
        ((O) this.b).close();
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public /* bridge */ /* synthetic */ void onSuccess(Object obj) {
    }

    public androidx.core.view.accessibility.e q(int i) {
        return null;
    }

    public File r(String str) {
        File file = new File(x(), p(str, b.JSON, false));
        if (file.exists()) {
            return file;
        }
        File file2 = new File(x(), p(str, b.ZIP, false));
        if (file2.exists()) {
            return file2;
        }
        File file3 = new File(x(), p(str, b.GZIP, false));
        if (file3.exists()) {
            return file3;
        }
        return null;
    }

    public boolean s(Uri uri) {
        com.amazon.aps.ads.util.adview.e eVar = (com.amazon.aps.ads.util.adview.e) this.b;
        Intrinsics.checkNotNullParameter(uri, "uri");
        try {
            try {
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setData(uri);
                eVar.getAdViewContext().startActivity(intent);
                eVar.onAdLeftApplication();
                return true;
            } catch (ActivityNotFoundException unused) {
                AbstractC3544v.a(eVar.getAdViewContext(), uri);
                eVar.onAdLeftApplication();
                return true;
            }
        } catch (RuntimeException unused2) {
            AbstractC3538u.a(this, "App stores and browsers not found");
            return false;
        }
    }

    public void t(Uri uri, String url) {
        int iM;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intent intent = new Intent("android.intent.action.VIEW");
        intent.setData(uri);
        com.amazon.aps.ads.util.adview.e eVar = (com.amazon.aps.ads.util.adview.e) this.b;
        if (eVar.getAdViewContext().getPackageManager().getLaunchIntentForPackage("com.amazon.mShop.android.shopping") == null && (iM = StringsKt.M(url, "products/", 0, false, 6)) > 0) {
            String strSubstring = url.substring(iM + 9);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
            intent.setData(Uri.parse(Intrinsics.k(strSubstring, "https://www.amazon.com/dp/")));
        }
        eVar.getAdViewContext().startActivity(intent);
        eVar.onAdLeftApplication();
    }

    public boolean u(String url) {
        int i;
        Intrinsics.checkNotNullParameter(url, "url");
        int iM = StringsKt.M(url, "//", 0, false, 6);
        if (iM < 0 || (i = iM + 2) >= url.length()) {
            return false;
        }
        String strSubstring = url.substring(i);
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse(Intrinsics.k(strSubstring, DtbConstants.HTTPS)));
        com.amazon.aps.ads.util.adview.e eVar = (com.amazon.aps.ads.util.adview.e) this.b;
        eVar.getAdViewContext().startActivity(intent);
        eVar.onAdLeftApplication();
        return true;
    }

    public boolean v(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        try {
            Intrinsics.checkNotNullParameter(url, "url");
            Uri uri = Uri.parse(url);
            Intrinsics.checkNotNullExpressionValue(uri, "parse(url)");
            if (uri != null && uri.getScheme() != null) {
                String scheme = uri.getScheme();
                if (Intrinsics.b(scheme, "com.amazon.mobile.shopping.web")) {
                    return u(url);
                }
                if (Intrinsics.b(scheme, "com.amazon.mobile.shopping")) {
                    t(uri, url);
                    return true;
                }
                if (Intrinsics.b(scheme, "market") ? true : Intrinsics.b(scheme, "amzn")) {
                    return s(uri);
                }
                Intrinsics.checkNotNullParameter(uri, "uri");
                Intent intent = new Intent("android.intent.action.VIEW");
                intent.setData(uri);
                com.amazon.aps.ads.util.adview.e eVar = (com.amazon.aps.ads.util.adview.e) this.b;
                eVar.getAdViewContext().startActivity(intent);
                eVar.onAdLeftApplication();
                return true;
            }
            return false;
        } catch (Exception unused) {
            return false;
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        boolean z;
        boolean z2;
        D0 d0F = d0;
        switch (this.a) {
            case 1:
                int iD = d0F.d();
                B b = (B) this.b;
                b.getClass();
                int iD2 = d0F.d();
                ActionBarContextView actionBarContextView = b.v;
                if (actionBarContextView == null || !(actionBarContextView.getLayoutParams() instanceof ViewGroup.MarginLayoutParams)) {
                    z = false;
                } else {
                    ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) b.v.getLayoutParams();
                    if (b.v.isShown()) {
                        if (b.m1 == null) {
                            b.m1 = new Rect();
                            b.n1 = new Rect();
                        }
                        Rect rect = b.m1;
                        Rect rect2 = b.n1;
                        rect.set(d0F.b(), d0F.d(), d0F.c(), d0F.a());
                        ViewGroup viewGroup = b.A;
                        if (Build.VERSION.SDK_INT >= 29) {
                            boolean z3 = C1.a;
                            B1.a(viewGroup, rect, rect2);
                        } else {
                            if (!C1.a) {
                                C1.a = true;
                                try {
                                    Method declaredMethod = View.class.getDeclaredMethod("computeFitSystemWindows", Rect.class, Rect.class);
                                    C1.b = declaredMethod;
                                    if (!declaredMethod.isAccessible()) {
                                        C1.b.setAccessible(true);
                                    }
                                } catch (NoSuchMethodException unused) {
                                }
                            }
                            Method method = C1.b;
                            if (method != null) {
                                try {
                                    method.invoke(viewGroup, rect, rect2);
                                } catch (Exception unused2) {
                                }
                            }
                        }
                        int i = rect.top;
                        int i2 = rect.left;
                        int i3 = rect.right;
                        ViewGroup viewGroup2 = b.A;
                        WeakHashMap weakHashMap = V.a;
                        D0 d0A = M.a(viewGroup2);
                        int iB = d0A == null ? 0 : d0A.b();
                        int iC = d0A == null ? 0 : d0A.c();
                        if (marginLayoutParams.topMargin == i && marginLayoutParams.leftMargin == i2 && marginLayoutParams.rightMargin == i3) {
                            z2 = false;
                        } else {
                            marginLayoutParams.topMargin = i;
                            marginLayoutParams.leftMargin = i2;
                            marginLayoutParams.rightMargin = i3;
                            z2 = true;
                        }
                        Context context = b.k;
                        if (i <= 0 || b.C != null) {
                            View view2 = b.C;
                            if (view2 != null) {
                                ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) view2.getLayoutParams();
                                int i4 = marginLayoutParams2.height;
                                int i5 = marginLayoutParams.topMargin;
                                if (i4 != i5 || marginLayoutParams2.leftMargin != iB || marginLayoutParams2.rightMargin != iC) {
                                    marginLayoutParams2.height = i5;
                                    marginLayoutParams2.leftMargin = iB;
                                    marginLayoutParams2.rightMargin = iC;
                                    b.C.setLayoutParams(marginLayoutParams2);
                                }
                            }
                        } else {
                            View view3 = new View(context);
                            b.C = view3;
                            view3.setVisibility(8);
                            FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, marginLayoutParams.topMargin, 51);
                            layoutParams.leftMargin = iB;
                            layoutParams.rightMargin = iC;
                            b.A.addView(b.C, -1, layoutParams);
                        }
                        View view4 = b.C;
                        z = view4 != null;
                        if (z && view4.getVisibility() != 0) {
                            View view5 = b.C;
                            view5.setBackgroundColor((view5.getWindowSystemUiVisibility() & 8192) != 0 ? context.getColor(R.color.abc_decor_view_status_guard_light) : context.getColor(R.color.abc_decor_view_status_guard));
                        }
                        if (!b.H && z) {
                            iD2 = 0;
                        }
                        z = z;
                        z = z2;
                    } else if (marginLayoutParams.topMargin != 0) {
                        marginLayoutParams.topMargin = 0;
                        z = false;
                    } else {
                        z = false;
                        z = false;
                    }
                    if (z) {
                        b.v.setLayoutParams(marginLayoutParams);
                    }
                }
                View view6 = b.C;
                if (view6 != null) {
                    view6.setVisibility(z ? 0 : 8);
                }
                if (iD != iD2) {
                    d0F = d0F.f(d0F.b(), iD2, d0F.c(), d0F.a());
                }
                return V.j(d0F, view);
            default:
                int iA = d0F.a();
                com.google.android.material.snackbar.g gVar = (com.google.android.material.snackbar.g) this.b;
                gVar.m = iA;
                gVar.n = d0F.b();
                gVar.o = d0F.c();
                gVar.f();
                return d0F;
        }
    }

    public File x() {
        o oVar = (o) this.b;
        oVar.getClass();
        File file = new File(oVar.a.getCacheDir(), "lottie_network_cache");
        if (file.isFile()) {
            file.delete();
        }
        if (!file.exists()) {
            file.mkdirs();
        }
        return file;
    }

    public boolean y(int i, int i2, Bundle bundle) {
        return false;
    }

    public C3083y1 z(com.quizlet.data.repository.qclass.c cVar, C0971v c0971v) {
        long jC;
        boolean z;
        long j;
        ArrayList arrayList = (ArrayList) cVar.b;
        C0219q c0219q = new C0219q(arrayList.size());
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            androidx.compose.ui.input.pointer.p pVar = (androidx.compose.ui.input.pointer.p) arrayList.get(i);
            long j2 = pVar.a;
            C0219q c0219q2 = (C0219q) this.b;
            androidx.compose.ui.input.pointer.o oVar = (androidx.compose.ui.input.pointer.o) c0219q2.c(j2);
            if (oVar == null) {
                long j3 = pVar.b;
                jC = pVar.d;
                j = j3;
                z = false;
            } else {
                jC = c0971v.C(oVar.b);
                long j4 = oVar.a;
                z = oVar.c;
                j = j4;
            }
            long j5 = jC;
            ArrayList arrayList2 = pVar.i;
            long j6 = pVar.j;
            long j7 = pVar.k;
            int i2 = i;
            long j8 = pVar.a;
            ArrayList arrayList3 = arrayList;
            int i3 = size;
            c0219q.g(j8, new androidx.compose.ui.input.pointer.n(j8, pVar.b, pVar.d, pVar.e, pVar.f, j, j5, z, pVar.g, arrayList2, j6, j7));
            long j9 = pVar.a;
            boolean z2 = pVar.e;
            if (z2) {
                c0219q2.g(j9, new androidx.compose.ui.input.pointer.o(pVar.b, pVar.c, z2));
            } else {
                c0219q2.h(j9);
            }
            i = i2 + 1;
            arrayList = arrayList3;
            size = i3;
        }
        return new C3083y1(3, c0219q, cVar);
    }

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public c(com.amazon.aps.ads.util.adview.e webviewClientListener) {
        this.a = 14;
        Intrinsics.checkNotNullParameter(webviewClientListener, "webviewClientListener");
        this.b = webviewClientListener;
    }

    public c(Function1 produceNewData) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(produceNewData, "produceNewData");
        this.b = produceNewData;
    }

    public c(i0 i0Var) {
        this.a = 5;
        this.b = (CaptureSessionOnClosedNotCalledQuirk) i0Var.b(CaptureSessionOnClosedNotCalledQuirk.class);
    }

    public c(int i) {
        this.a = i;
        switch (i) {
            case 10:
                break;
            case 11:
                this.b = new androidx.core.view.accessibility.f(this);
                break;
            case 13:
                this.b = null;
                break;
            case 15:
                this.b = new HashMap();
                new HashMap();
                break;
            case 16:
                this.b = ByteBuffer.allocate(8);
                break;
            case 29:
                this.b = new com.google.zxing.oned.f(0);
                break;
            default:
                this.b = new C0219q((Object) null);
                break;
        }
    }
}
