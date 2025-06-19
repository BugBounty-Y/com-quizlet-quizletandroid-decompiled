package com.google.android.gms.common.internal;

import android.net.Uri;

/* loaded from: classes2.dex */
public abstract class v {
    public static final Uri a = new Uri.Builder().scheme("content").authority("com.google.android.gms.chimera").build();

    /* JADX WARN: Removed duplicated region for block: B:25:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b3 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.content.Intent a(android.content.Context r5, com.google.android.gms.common.internal.B r6) throws com.google.android.gms.common.internal.zzaf, android.os.RemoteException {
        /*
            java.lang.String r0 = "ServiceBindIntentUtils"
            java.lang.String r1 = r6.a
            r2 = 0
            if (r1 != 0) goto L11
            android.content.Intent r5 = new android.content.Intent
            r5.<init>()
            android.content.Intent r5 = r5.setComponent(r2)
            return r5
        L11:
            boolean r3 = r6.c
            if (r3 == 0) goto La5
            android.os.Bundle r3 = new android.os.Bundle
            r3.<init>()
            java.lang.String r4 = "serviceActionBundleKey"
            r3.putString(r4, r1)
            android.content.ContentResolver r5 = r5.getContentResolver()     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            android.net.Uri r4 = com.google.android.gms.common.internal.v.a     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            android.content.ContentProviderClient r5 = r5.acquireUnstableContentProviderClient(r4)     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            if (r5 == 0) goto L3e
            java.lang.String r4 = "serviceIntentCall"
            android.os.Bundle r3 = r5.call(r4, r2, r3)     // Catch: java.lang.Throwable -> L39
            r5.release()     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            goto L54
        L35:
            r5 = move-exception
            goto L46
        L37:
            r5 = move-exception
            goto L46
        L39:
            r3 = move-exception
            r5.release()     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            throw r3     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
        L3e:
            android.os.RemoteException r5 = new android.os.RemoteException     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            java.lang.String r3 = "Failed to acquire ContentProviderClient"
            r5.<init>(r3)     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
            throw r5     // Catch: java.lang.IllegalArgumentException -> L35 android.os.RemoteException -> L37
        L46:
            java.lang.String r3 = "Dynamic intent resolution failed: "
            java.lang.String r5 = r5.toString()
            java.lang.String r5 = r3.concat(r5)
            android.util.Log.w(r0, r5)
            r3 = r2
        L54:
            if (r3 != 0) goto L57
            goto L6d
        L57:
            java.lang.String r5 = "serviceResponseIntentKey"
            android.os.Parcelable r5 = r3.getParcelable(r5)
            android.content.Intent r5 = (android.content.Intent) r5
            if (r5 == 0) goto L63
            r2 = r5
            goto L6d
        L63:
            java.lang.String r5 = "serviceMissingResolutionIntentKey"
            android.os.Parcelable r5 = r3.getParcelable(r5)
            android.app.PendingIntent r5 = (android.app.PendingIntent) r5
            if (r5 != 0) goto L79
        L6d:
            if (r2 != 0) goto La5
            java.lang.String r5 = "Dynamic lookup for intent failed for action: "
            java.lang.String r5 = r5.concat(r1)
            android.util.Log.w(r0, r5)
            goto La5
        L79:
            int r6 = r1.length()
            java.lang.StringBuilder r2 = new java.lang.StringBuilder
            int r6 = r6 + 72
            r2.<init>(r6)
            java.lang.String r6 = "Dynamic lookup for intent failed for action "
            r2.append(r6)
            r2.append(r1)
            java.lang.String r6 = " but has possible resolution"
            r2.append(r6)
            java.lang.String r6 = r2.toString()
            android.util.Log.w(r0, r6)
            com.google.android.gms.common.internal.zzaf r6 = new com.google.android.gms.common.internal.zzaf
            com.google.android.gms.common.ConnectionResult r0 = new com.google.android.gms.common.ConnectionResult
            r1 = 25
            r0.<init>(r1, r5)
            r6.<init>(r0)
            throw r6
        La5:
            if (r2 != 0) goto Lb3
            android.content.Intent r5 = new android.content.Intent
            r5.<init>(r1)
            java.lang.String r6 = r6.b
            android.content.Intent r5 = r5.setPackage(r6)
            return r5
        Lb3:
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.common.internal.v.a(android.content.Context, com.google.android.gms.common.internal.B):android.content.Intent");
    }
}
