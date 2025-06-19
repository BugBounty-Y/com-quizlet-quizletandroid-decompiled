package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.Intent;

/* renamed from: com.google.android.gms.internal.ads.r7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2558r7 {
    public final Context a;

    public C2558r7(Context context) {
        com.google.android.gms.common.internal.u.i(context, "Context can not be null");
        this.a = context;
    }

    public final boolean a(Intent intent) {
        com.google.android.gms.common.internal.u.i(intent, "Intent can not be null");
        return !this.a.getPackageManager().queryIntentActivities(intent, 0).isEmpty();
    }

    public final boolean b() {
        CallableC2516q7 callableC2516q7 = new CallableC2516q7(0);
        Context context = this.a;
        return ((Boolean) com.google.android.gms.internal.mlkit_vision_common.X2.d(context, callableC2516q7)).booleanValue() && com.google.android.gms.common.wrappers.c.a(context).a.checkCallingOrSelfPermission("android.permission.WRITE_EXTERNAL_STORAGE") == 0;
    }
}
