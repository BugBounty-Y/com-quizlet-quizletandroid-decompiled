package androidx.camera.camera2.interop;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import androidx.camera.camera2.internal.C0137n;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.util.BinderC1634j;
import com.google.android.gms.ads.internal.util.C;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.ads.internal.util.k;
import com.google.android.gms.ads.internal.util.o;
import com.google.android.gms.ads.internal.util.q;
import com.google.android.gms.ads.internal.util.t;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2493pl;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.EnumC2450ol;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public final Object a;
    public boolean b;
    public boolean c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;

    public c() {
        this.a = new Object();
        this.d = "";
        this.e = "";
        this.b = false;
        this.c = false;
        this.f = "";
    }

    public static void e(Context context, String str, boolean z, boolean z2) {
        if (context instanceof Activity) {
            F.l.post(new k(context, str, z, z2));
        } else {
            i.g("Can not create dialog without Activity Context");
        }
    }

    public static final String j(Context context, String str, String str2) {
        HashMap map = new HashMap();
        map.put("User-Agent", j.C.c.y(context, str2));
        new q(context);
        o oVarA = q.a(0, str, map, null);
        try {
            return (String) oVarA.a.get(((Integer) r.d.c.a(AbstractC2773w7.W4)).intValue(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            i.f("Interrupted while retrieving a response from: ".concat(String.valueOf(str)), e);
            oVarA.cancel(true);
            return null;
        } catch (TimeoutException e2) {
            i.f("Timeout while retrieving a response from: ".concat(String.valueOf(str)), e2);
            oVarA.cancel(true);
            return null;
        } catch (Exception e3) {
            i.f("Error retrieving a response from: ".concat(String.valueOf(str)), e3);
            return null;
        }
    }

    public void a(Context context) {
        C2493pl c2493pl;
        if (!((Boolean) r.d.c.a(AbstractC2773w7.j9)).booleanValue() || (c2493pl = (C2493pl) this.g) == null) {
            return;
        }
        c2493pl.d(new BinderC1634j(this, context), EnumC2450ol.d);
    }

    public void b(Context context, String str, String str2) {
        F f = j.C.c;
        F.r(context, k(context, (String) r.d.c.a(AbstractC2773w7.S4), str, str2));
    }

    public void c(Context context, String str, String str2, String str3) {
        Uri.Builder builderBuildUpon = k(context, (String) r.d.c.a(AbstractC2773w7.V4), str3, str).buildUpon();
        builderBuildUpon.appendQueryParameter("debugData", str2);
        F f = j.C.c;
        new t(context, str, builderBuildUpon.build().toString(), null).R();
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0038  */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0039 A[Catch: all -> 0x0047, TryCatch #0 {all -> 0x0047, blocks: (B:4:0x0003, B:6:0x0017, B:8:0x0028, B:11:0x002e, B:13:0x0034, B:16:0x0039, B:17:0x003d, B:19:0x0043, B:22:0x0049), top: B:26:0x0003 }] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0043 A[Catch: all -> 0x0047, TryCatch #0 {all -> 0x0047, blocks: (B:4:0x0003, B:6:0x0017, B:8:0x0028, B:11:0x002e, B:13:0x0034, B:16:0x0039, B:17:0x003d, B:19:0x0043, B:22:0x0049), top: B:26:0x0003 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void d(boolean r4) {
        /*
            r3 = this;
            java.lang.Object r0 = r3.a
            monitor-enter(r0)
            r3.c = r4     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.internal.ads.s7 r1 = com.google.android.gms.internal.ads.AbstractC2773w7.j9     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.ads.internal.client.r r2 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.internal.ads.u7 r2 = r2.c     // Catch: java.lang.Throwable -> L47
            java.lang.Object r1 = r2.a(r1)     // Catch: java.lang.Throwable -> L47
            java.lang.Boolean r1 = (java.lang.Boolean) r1     // Catch: java.lang.Throwable -> L47
            boolean r1 = r1.booleanValue()     // Catch: java.lang.Throwable -> L47
            if (r1 == 0) goto L49
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.internal.ads.ed r1 = r1.h     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.ads.internal.util.C r1 = r1.d()     // Catch: java.lang.Throwable -> L47
            r1.r(r4)     // Catch: java.lang.Throwable -> L47
            java.lang.Object r1 = r3.g     // Catch: java.lang.Throwable -> L47
            com.google.android.gms.internal.ads.pl r1 = (com.google.android.gms.internal.ads.C2493pl) r1     // Catch: java.lang.Throwable -> L47
            if (r1 == 0) goto L49
            boolean r2 = r1.u     // Catch: java.lang.Throwable -> L47
            if (r2 != 0) goto L32
            if (r4 == 0) goto L3d
            r1.h()     // Catch: java.lang.Throwable -> L47
            goto L34
        L32:
            if (r4 == 0) goto L3d
        L34:
            boolean r4 = r1.s     // Catch: java.lang.Throwable -> L47
            if (r4 == 0) goto L39
            goto L3d
        L39:
            r1.m()     // Catch: java.lang.Throwable -> L47
            goto L49
        L3d:
            boolean r4 = r1.f()     // Catch: java.lang.Throwable -> L47
            if (r4 != 0) goto L49
            r1.l()     // Catch: java.lang.Throwable -> L47
            goto L49
        L47:
            r4 = move-exception
            goto L4b
        L49:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L47
            return
        L4b:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L47
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.interop.c.d(boolean):void");
    }

    public boolean f(Context context, String str, String str2) {
        C2601s7 c2601s7 = AbstractC2773w7.U4;
        r rVar = r.d;
        String strJ = j(context, k(context, (String) rVar.c.a(c2601s7), str, str2).toString(), str2);
        if (TextUtils.isEmpty(strJ)) {
            i.d("Not linked for debug signals.");
            return false;
        }
        try {
            boolean zEquals = "1".equals(new JSONObject(strJ.trim()).optString("debug_mode"));
            d(zEquals);
            if (((Boolean) rVar.c.a(AbstractC2773w7.j9)).booleanValue()) {
                C cD = j.C.h.d();
                if (true != zEquals) {
                    str = "";
                }
                cD.q(str);
            }
            return zEquals;
        } catch (JSONException e) {
            i.i("Fail to get debug mode response json.", e);
            return false;
        }
    }

    public boolean g() {
        boolean z;
        synchronized (this.a) {
            z = this.c;
        }
        return z;
    }

    public boolean h() {
        boolean z;
        synchronized (this.a) {
            z = this.b;
        }
        return z;
    }

    public boolean i(Context context, String str, String str2, String str3) {
        if (TextUtils.isEmpty(str2) || !h()) {
            return false;
        }
        i.d("Sending troubleshooting signals to the server.");
        c(context, str, str2, str3);
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x006d A[Catch: all -> 0x0034, TryCatch #0 {, blocks: (B:4:0x000b, B:6:0x0015, B:7:0x001b, B:12:0x003d, B:14:0x0045, B:16:0x0056, B:19:0x0068, B:11:0x0036, B:20:0x006d, B:21:0x0071), top: B:26:0x000b, inners: #1, #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public android.net.Uri k(android.content.Context r6, java.lang.String r7, java.lang.String r8, java.lang.String r9) {
        /*
            r5 = this;
            android.net.Uri r7 = android.net.Uri.parse(r7)
            android.net.Uri$Builder r7 = r7.buildUpon()
            java.lang.Object r0 = r5.a
            monitor-enter(r0)
            java.lang.Object r1 = r5.d     // Catch: java.lang.Throwable -> L34
            java.lang.String r1 = (java.lang.String) r1     // Catch: java.lang.Throwable -> L34
            boolean r1 = android.text.TextUtils.isEmpty(r1)     // Catch: java.lang.Throwable -> L34
            if (r1 == 0) goto L6d
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L34
            com.google.android.gms.ads.internal.util.F r1 = r1.c     // Catch: java.lang.Throwable -> L34
            java.lang.String r1 = "debug_signals_id.txt"
            java.io.FileInputStream r1 = r6.openFileInput(r1)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            java.lang.String r2 = new java.lang.String     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            java.io.ByteArrayOutputStream r3 = new java.io.ByteArrayOutputStream     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            r3.<init>()     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            r4 = 1
            com.google.android.gms.common.util.c.e(r1, r3, r4)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            byte[] r1 = r3.toByteArray()     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            java.lang.String r3 = "UTF-8"
            r2.<init>(r1, r3)     // Catch: java.lang.Throwable -> L34 java.io.IOException -> L36
            goto L3d
        L34:
            r6 = move-exception
            goto L86
        L36:
            java.lang.String r1 = "Error reading from internal storage."
            com.google.android.gms.ads.internal.util.client.i.d(r1)     // Catch: java.lang.Throwable -> L34
            java.lang.String r2 = ""
        L3d:
            r5.d = r2     // Catch: java.lang.Throwable -> L34
            boolean r1 = android.text.TextUtils.isEmpty(r2)     // Catch: java.lang.Throwable -> L34
            if (r1 == 0) goto L6d
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C     // Catch: java.lang.Throwable -> L34
            com.google.android.gms.ads.internal.util.F r1 = r1.c     // Catch: java.lang.Throwable -> L34
            java.util.UUID r1 = java.util.UUID.randomUUID()     // Catch: java.lang.Throwable -> L34
            java.lang.String r1 = r1.toString()     // Catch: java.lang.Throwable -> L34
            r5.d = r1     // Catch: java.lang.Throwable -> L34
            java.lang.String r2 = "debug_signals_id.txt"
            r3 = 0
            java.io.FileOutputStream r6 = r6.openFileOutput(r2, r3)     // Catch: java.lang.Throwable -> L34 java.lang.Exception -> L67
            java.lang.String r2 = "UTF-8"
            byte[] r1 = r1.getBytes(r2)     // Catch: java.lang.Throwable -> L34 java.lang.Exception -> L67
            r6.write(r1)     // Catch: java.lang.Throwable -> L34 java.lang.Exception -> L67
            r6.close()     // Catch: java.lang.Throwable -> L34 java.lang.Exception -> L67
            goto L6d
        L67:
            r6 = move-exception
            java.lang.String r1 = "Error writing to file in internal storage."
            com.google.android.gms.ads.internal.util.client.i.f(r1, r6)     // Catch: java.lang.Throwable -> L34
        L6d:
            java.lang.Object r6 = r5.d     // Catch: java.lang.Throwable -> L34
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Throwable -> L34
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L34
            java.lang.String r0 = "linkedDeviceId"
            r7.appendQueryParameter(r0, r6)
            java.lang.String r6 = "adSlotPath"
            r7.appendQueryParameter(r6, r8)
            java.lang.String r6 = "afmaVersion"
            r7.appendQueryParameter(r6, r9)
            android.net.Uri r6 = r7.build()
            return r6
        L86:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L34
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.camera2.interop.c.k(android.content.Context, java.lang.String, java.lang.String, java.lang.String):android.net.Uri");
    }

    public c(C0137n c0137n, androidx.camera.core.impl.utils.executor.k kVar) {
        this.b = false;
        this.c = false;
        this.a = new Object();
        this.f = new androidx.camera.camera2.impl.a(0);
        this.d = c0137n;
        this.e = kVar;
    }
}
