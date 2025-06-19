package com.facebook.appevents.iap;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ s b;
    public final /* synthetic */ Context c;

    public /* synthetic */ e(s sVar, Context context, int i) {
        this.a = i;
        this.b = sVar;
        this.c = context;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                s billingClientVersion = this.b;
                Context context = this.c;
                if (!com.facebook.internal.instrument.crashshield.a.b(f.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(billingClientVersion, "$billingClientVersion");
                        Intrinsics.checkNotNullParameter(context, "$context");
                        f fVar = f.a;
                        String packageName = context.getPackageName();
                        Intrinsics.checkNotNullExpressionValue(packageName, "context.packageName");
                        fVar.a(billingClientVersion, packageName);
                        break;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(f.class, th);
                        return;
                    }
                }
                break;
            default:
                s billingClientVersion2 = this.b;
                Context context2 = this.c;
                if (!com.facebook.internal.instrument.crashshield.a.b(f.class)) {
                    try {
                        Intrinsics.checkNotNullParameter(billingClientVersion2, "$billingClientVersion");
                        Intrinsics.checkNotNullParameter(context2, "$context");
                        f fVar2 = f.a;
                        String packageName2 = context2.getPackageName();
                        Intrinsics.checkNotNullExpressionValue(packageName2, "context.packageName");
                        fVar2.a(billingClientVersion2, packageName2);
                        break;
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(f.class, th2);
                    }
                }
                break;
        }
    }
}
