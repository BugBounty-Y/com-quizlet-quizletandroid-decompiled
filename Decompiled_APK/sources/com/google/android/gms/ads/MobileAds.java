package com.google.android.gms.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C0;

/* loaded from: classes2.dex */
public class MobileAds {
    /* JADX WARN: Removed duplicated region for block: B:36:0x008f A[Catch: all -> 0x0076, TryCatch #2 {, blocks: (B:21:0x0041, B:23:0x0060, B:34:0x007e, B:36:0x008f, B:38:0x00a1, B:45:0x00e8, B:39:0x00b3, B:41:0x00c1, B:43:0x00d3, B:44:0x00e0, B:25:0x0064, B:28:0x0070, B:33:0x0079), top: B:56:0x0041, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b3 A[Catch: all -> 0x0076, TryCatch #2 {, blocks: (B:21:0x0041, B:23:0x0060, B:34:0x007e, B:36:0x008f, B:38:0x00a1, B:45:0x00e8, B:39:0x00b3, B:41:0x00c1, B:43:0x00d3, B:44:0x00e0, B:25:0x0064, B:28:0x0070, B:33:0x0079), top: B:56:0x0041, inners: #3 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00e0 A[Catch: all -> 0x0076, TryCatch #2 {, blocks: (B:21:0x0041, B:23:0x0060, B:34:0x007e, B:36:0x008f, B:38:0x00a1, B:45:0x00e8, B:39:0x00b3, B:41:0x00c1, B:43:0x00d3, B:44:0x00e0, B:25:0x0064, B:28:0x0070, B:33:0x0079), top: B:56:0x0041, inners: #3 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void a(android.app.Activity r4, com.quizlet.quizletandroid.initializers.ads.a r5) {
        /*
            Method dump skipped, instructions count: 246
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.ads.MobileAds.a(android.app.Activity, com.quizlet.quizletandroid.initializers.ads.a):void");
    }

    private static void setPlugin(String str) {
        C0 c0E = C0.e();
        synchronized (c0E.e) {
            com.google.android.gms.common.internal.u.j("MobileAds.initialize() must be called prior to setting the plugin.", c0E.f != null);
            try {
                c0E.f.M(str);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Unable to set plugin.", e);
            }
        }
    }
}
