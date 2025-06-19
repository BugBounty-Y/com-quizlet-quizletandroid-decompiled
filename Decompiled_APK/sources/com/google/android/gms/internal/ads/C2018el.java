package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.RemoteException;
import android.util.Base64;
import java.io.ByteArrayOutputStream;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.el, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2018el {
    public final Context a;
    public final ApplicationInfo b;
    public final int c;
    public final int d;
    public String e = "";

    public C2018el(Context context) {
        this.a = context;
        this.b = context.getApplicationInfo();
        C2601s7 c2601s7 = AbstractC2773w7.h9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.c = ((Integer) rVar.c.a(c2601s7)).intValue();
        this.d = ((Integer) rVar.c.a(AbstractC2773w7.i9)).intValue();
    }

    public final JSONObject a() throws JSONException, PackageManager.NameNotFoundException {
        String strG;
        String strEncodeToString;
        ApplicationInfo applicationInfo = this.b;
        Context context = this.a;
        JSONObject jSONObject = new JSONObject();
        try {
            String str = applicationInfo.packageName;
            com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
            jSONObject.put("name", com.google.android.gms.common.wrappers.c.a(context).b(str));
        } catch (PackageManager.NameNotFoundException unused) {
        }
        jSONObject.put("packageName", applicationInfo.packageName);
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        Drawable applicationIcon = null;
        try {
            strG = com.google.android.gms.ads.internal.util.F.G(context);
        } catch (RemoteException unused2) {
            strG = null;
        }
        jSONObject.put("adMobAppId", strG);
        boolean zIsEmpty = this.e.isEmpty();
        int i = this.d;
        int i2 = this.c;
        if (zIsEmpty) {
            try {
                com.google.android.gms.common.wrappers.b bVarA = com.google.android.gms.common.wrappers.c.a(context);
                String str2 = applicationInfo.packageName;
                Context context2 = bVarA.a;
                ApplicationInfo applicationInfo2 = context2.getPackageManager().getApplicationInfo(str2, 0);
                context2.getPackageManager().getApplicationLabel(applicationInfo2);
                applicationIcon = context2.getPackageManager().getApplicationIcon(applicationInfo2);
            } catch (PackageManager.NameNotFoundException unused3) {
            }
            if (applicationIcon == null) {
                strEncodeToString = "";
            } else {
                applicationIcon.setBounds(0, 0, i2, i);
                Bitmap bitmapCreateBitmap = Bitmap.createBitmap(i2, i, Bitmap.Config.ARGB_8888);
                applicationIcon.draw(new Canvas(bitmapCreateBitmap));
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                bitmapCreateBitmap.compress(Bitmap.CompressFormat.PNG, 100, byteArrayOutputStream);
                strEncodeToString = Base64.encodeToString(byteArrayOutputStream.toByteArray(), 2);
            }
            this.e = strEncodeToString;
        }
        if (!this.e.isEmpty()) {
            jSONObject.put("icon", this.e);
            jSONObject.put("iconWidthPx", i2);
            jSONObject.put("iconHeightPx", i);
        }
        return jSONObject;
    }
}
