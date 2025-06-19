package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.WindowManager;
import com.google.android.gms.ads.internal.client.C1614q;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.qb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2526qb extends Fi implements InterfaceC2389n9 {
    public final C2743ve d;
    public final Context e;
    public final WindowManager f;
    public final C2558r7 g;
    public DisplayMetrics h;
    public float i;
    public int j;
    public int k;
    public int l;
    public int m;
    public int n;
    public int o;
    public int p;

    public C2526qb(C2743ve c2743ve, Context context, C2558r7 c2558r7) {
        super(9, c2743ve, "");
        this.j = -1;
        this.k = -1;
        this.m = -1;
        this.n = -1;
        this.o = -1;
        this.p = -1;
        this.d = c2743ve;
        this.e = context;
        this.g = c2558r7;
        this.f = (WindowManager) context.getSystemService("window");
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0063 A[PHI: r5
  0x0063: PHI (r5v2 int) = (r5v1 int), (r5v5 int) binds: [B:11:0x0042, B:17:0x0054] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void E(int r9, int r10) {
        /*
            r8 = this;
            android.content.Context r0 = r8.e
            boolean r1 = r0 instanceof android.app.Activity
            r2 = 0
            if (r1 == 0) goto L15
            com.google.android.gms.ads.internal.j r1 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.ads.internal.util.F r1 = r1.c
            r1 = r0
            android.app.Activity r1 = (android.app.Activity) r1
            int[] r1 = com.google.android.gms.ads.internal.util.F.o(r1)
            r1 = r1[r2]
            goto L16
        L15:
            r1 = r2
        L16:
            com.google.android.gms.internal.ads.ve r3 = r8.d
            com.google.android.gms.internal.ads.xe r4 = r3.a
            com.bumptech.glide.load.engine.cache.f r5 = r4.O()
            if (r5 == 0) goto L2a
            com.bumptech.glide.load.engine.cache.f r5 = r4.O()
            boolean r5 = r5.b()
            if (r5 != 0) goto L76
        L2a:
            int r5 = r3.getWidth()
            int r3 = r3.getHeight()
            com.google.android.gms.internal.ads.s7 r6 = com.google.android.gms.internal.ads.AbstractC2773w7.X
            com.google.android.gms.ads.internal.client.r r7 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r7 = r7.c
            java.lang.Object r6 = r7.a(r6)
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L63
            if (r5 != 0) goto L54
            com.bumptech.glide.load.engine.cache.f r5 = r4.O()
            if (r5 == 0) goto L53
            com.bumptech.glide.load.engine.cache.f r5 = r4.O()
            int r5 = r5.c
            goto L54
        L53:
            r5 = r2
        L54:
            if (r3 != 0) goto L63
            com.bumptech.glide.load.engine.cache.f r3 = r4.O()
            if (r3 == 0) goto L64
            com.bumptech.glide.load.engine.cache.f r2 = r4.O()
            int r2 = r2.b
            goto L64
        L63:
            r2 = r3
        L64:
            com.google.android.gms.ads.internal.client.q r3 = com.google.android.gms.ads.internal.client.C1614q.f
            com.google.android.gms.ads.internal.util.client.c r6 = r3.a
            int r5 = r6.f(r0, r5)
            r8.o = r5
            com.google.android.gms.ads.internal.util.client.c r3 = r3.a
            int r0 = r3.f(r0, r2)
            r8.p = r0
        L76:
            int r0 = r10 - r1
            int r1 = r8.o
            int r2 = r8.p
            org.json.JSONObject r3 = new org.json.JSONObject     // Catch: org.json.JSONException -> La3
            r3.<init>()     // Catch: org.json.JSONException -> La3
            java.lang.String r5 = "x"
            org.json.JSONObject r3 = r3.put(r5, r9)     // Catch: org.json.JSONException -> La3
            java.lang.String r5 = "y"
            org.json.JSONObject r0 = r3.put(r5, r0)     // Catch: org.json.JSONException -> La3
            java.lang.String r3 = "width"
            org.json.JSONObject r0 = r0.put(r3, r1)     // Catch: org.json.JSONException -> La3
            java.lang.String r1 = "height"
            org.json.JSONObject r0 = r0.put(r1, r2)     // Catch: org.json.JSONException -> La3
            java.lang.Object r1 = r8.b     // Catch: org.json.JSONException -> La3
            com.google.android.gms.internal.ads.qe r1 = (com.google.android.gms.internal.ads.InterfaceC2529qe) r1     // Catch: org.json.JSONException -> La3
            java.lang.String r2 = "onDefaultPositionReceived"
            r1.b(r2, r0)     // Catch: org.json.JSONException -> La3
            goto La9
        La3:
            r0 = move-exception
            java.lang.String r1 = "Error occurred while dispatching default position."
            com.google.android.gms.ads.internal.util.client.i.f(r1, r0)
        La9:
            com.google.android.gms.internal.ads.Be r0 = r4.n
            com.google.android.gms.internal.ads.nb r0 = r0.x
            if (r0 == 0) goto Lb3
            r0.f = r9
            r0.g = r10
        Lb3:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2526qb.E(int, int):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    public final void e(Object obj, Map map) throws JSONException {
        JSONObject jSONObjectPut;
        this.h = new DisplayMetrics();
        Display defaultDisplay = this.f.getDefaultDisplay();
        defaultDisplay.getMetrics(this.h);
        this.i = this.h.density;
        this.l = defaultDisplay.getRotation();
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        this.j = Math.round(r11.widthPixels / this.h.density);
        this.k = Math.round(r11.heightPixels / this.h.density);
        C2743ve c2743ve = this.d;
        Activity activityZzi = c2743ve.zzi();
        if (activityZzi == null || activityZzi.getWindow() == null) {
            this.m = this.j;
            this.n = this.k;
        } else {
            com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
            int[] iArrN = com.google.android.gms.ads.internal.util.F.n(activityZzi);
            this.m = Math.round(iArrN[0] / this.h.density);
            this.n = Math.round(iArrN[1] / this.h.density);
        }
        ViewTreeObserverOnGlobalLayoutListenerC2829xe viewTreeObserverOnGlobalLayoutListenerC2829xe = c2743ve.a;
        if (viewTreeObserverOnGlobalLayoutListenerC2829xe.O().b()) {
            this.o = this.j;
            this.p = this.k;
        } else {
            c2743ve.measure(0, 0);
        }
        y(this.j, this.k, this.m, this.n, this.i, this.l);
        Intent intent = new Intent("android.intent.action.DIAL");
        intent.setData(Uri.parse("tel:"));
        C2558r7 c2558r7 = this.g;
        boolean zA = c2558r7.a(intent);
        Intent intent2 = new Intent("android.intent.action.VIEW");
        intent2.setData(Uri.parse("sms:"));
        boolean zA2 = c2558r7.a(intent2);
        try {
            jSONObjectPut = new JSONObject().put("sms", zA2).put("tel", zA).put("calendar", c2558r7.a(new Intent("android.intent.action.INSERT").setType("vnd.android.cursor.dir/event"))).put("storePicture", c2558r7.b()).put("inlineVideo", true);
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while obtaining the MRAID capabilities.", e);
            jSONObjectPut = null;
        }
        c2743ve.b("onDeviceFeaturesReceived", jSONObjectPut);
        int[] iArr = new int[2];
        c2743ve.getLocationOnScreen(iArr);
        C1614q c1614q = C1614q.f;
        com.google.android.gms.ads.internal.util.client.c cVar2 = c1614q.a;
        int i = iArr[0];
        Context context = this.e;
        E(cVar2.f(context, i), c1614q.a.f(context, iArr[1]));
        if (com.google.android.gms.ads.internal.util.client.i.k(2)) {
            com.google.android.gms.ads.internal.util.client.i.g("Dispatching Ready Event.");
        }
        try {
            ((InterfaceC2529qe) this.b).b("onReadyEventReceived", new JSONObject().put("js", viewTreeObserverOnGlobalLayoutListenerC2829xe.e.a));
        } catch (JSONException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("Error occurred while dispatching ready Event.", e2);
        }
    }
}
