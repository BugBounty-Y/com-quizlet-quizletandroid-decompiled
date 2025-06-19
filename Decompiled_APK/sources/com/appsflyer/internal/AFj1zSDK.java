package com.appsflyer.internal;

import android.annotation.SuppressLint;
import android.content.Context;
import com.appsflyer.internal.AFj1xSDK;
import java.util.concurrent.ExecutorService;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFj1zSDK extends AFi1dSDK {

    @NotNull
    private final Runnable component3;

    @NotNull
    private final AFj1ySDK getCurrencyIso4217Code;

    @NotNull
    private final AFc1pSDK getMediationNetwork;

    @NotNull
    private final ExecutorService getMonetizationNetwork;
    private String hashCode;

    public /* synthetic */ class AFa1vSDK {
        public static final /* synthetic */ int[] getMonetizationNetwork;

        static {
            int[] iArr = new int[AFj1ySDK.values().length];
            try {
                iArr[AFj1ySDK.FACEBOOK.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[AFj1ySDK.INSTAGRAM.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[AFj1ySDK.FACEBOOK_LITE.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            getMonetizationNetwork = iArr;
        }
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AFj1zSDK(@NotNull AFc1pSDK aFc1pSDK, @NotNull ExecutorService executorService, @NotNull AFj1ySDK aFj1ySDK, @NotNull Runnable runnable, @NotNull Runnable runnable2) {
        String str;
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(executorService, "");
        Intrinsics.checkNotNullParameter(aFj1ySDK, "");
        Intrinsics.checkNotNullParameter(runnable, "");
        Intrinsics.checkNotNullParameter(runnable2, "");
        int i = AFj1xSDK.AFa1ySDK.getMonetizationNetwork[aFj1ySDK.ordinal()];
        if (i == 1) {
            str = "facebook";
        } else if (i == 2) {
            str = "instagram";
        } else {
            if (i != 3) {
                throw new NoWhenBranchMatchedException();
            }
            str = "facebook_lite";
        }
        super("app", str, aFc1pSDK, runnable);
        this.getMediationNetwork = aFc1pSDK;
        this.getMonetizationNetwork = executorService;
        this.getCurrencyIso4217Code = aFj1ySDK;
        this.component3 = runnable2;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x008d A[PHI: r0
  0x008d: PHI (r0v7 java.lang.String) = (r0v6 java.lang.String), (r0v13 java.lang.String), (r0v19 java.lang.String) binds: [B:14:0x003c, B:23:0x0063, B:32:0x008a] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final boolean AFAdRevenueData(android.content.Context r12) {
        /*
            r11 = this;
            boolean r0 = r11.getRevenue()
            r1 = 0
            if (r0 != 0) goto L14
            com.appsflyer.AFLogger r2 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r3 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r4 = "Referrer collection disallowed by counter."
            r5 = 0
            r6 = 4
            r7 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r2, r3, r4, r5, r6, r7)
            return r1
        L14:
            com.appsflyer.internal.AFc1pSDK r0 = r11.getMediationNetwork
            java.lang.String r2 = "com.facebook.sdk.ApplicationId"
            java.lang.String r0 = r0.getCurrencyIso4217Code(r2)
            java.lang.String r2 = "fb"
            r3 = 0
            if (r0 == 0) goto L26
            java.lang.String r0 = kotlin.text.StringsKt.T(r0, r2)
            goto L27
        L26:
            r0 = r3
        L27:
            if (r0 == 0) goto L2f
            int r4 = r0.length()
            if (r4 != 0) goto L3c
        L2f:
            com.appsflyer.AFLogger r5 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r6 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r7 = "Facebook app id Manifest metadata is not found."
            r8 = 0
            r9 = 4
            r10 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r5, r6, r7, r8, r9, r10)
            r0 = r3
        L3c:
            if (r0 != 0) goto L8d
            com.appsflyer.internal.AFc1pSDK r0 = r11.getMediationNetwork
            java.lang.String r4 = "facebook_application_id"
            java.lang.String r0 = r0.getRevenue(r4)
            if (r0 == 0) goto L4d
            java.lang.String r0 = kotlin.text.StringsKt.T(r0, r2)
            goto L4e
        L4d:
            r0 = r3
        L4e:
            if (r0 == 0) goto L56
            int r4 = r0.length()
            if (r4 != 0) goto L63
        L56:
            com.appsflyer.AFLogger r5 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r6 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r7 = "Facebook app id string resource is not found."
            r8 = 0
            r9 = 4
            r10 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r5, r6, r7, r8, r9, r10)
            r0 = r3
        L63:
            if (r0 != 0) goto L8d
            com.appsflyer.internal.AFc1pSDK r0 = r11.getMediationNetwork
            java.lang.String r4 = "com.appsflyer.FacebookApplicationId"
            java.lang.String r0 = r0.getCurrencyIso4217Code(r4)
            if (r0 == 0) goto L74
            java.lang.String r0 = kotlin.text.StringsKt.T(r0, r2)
            goto L75
        L74:
            r0 = r3
        L75:
            if (r0 == 0) goto L7d
            int r2 = r0.length()
            if (r2 != 0) goto L8a
        L7d:
            com.appsflyer.AFLogger r4 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r5 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r6 = "AF Facebook app id Manifest metadata is not found."
            r7 = 0
            r8 = 4
            r9 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r4, r5, r6, r7, r8, r9)
            r0 = r3
        L8a:
            if (r0 != 0) goto L8d
            goto L8e
        L8d:
            r3 = r0
        L8e:
            r11.hashCode = r3
            if (r3 != 0) goto L9f
            com.appsflyer.AFLogger r4 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r5 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r6 = "Referrer collection disallowed by missing Facebook app id."
            r7 = 0
            r8 = 4
            r9 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r4, r5, r6, r7, r8, r9)
            return r1
        L9f:
            boolean r12 = r11.getCurrencyIso4217Code(r12)
            if (r12 != 0) goto Lb2
            com.appsflyer.AFLogger r2 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r3 = com.appsflyer.internal.AFg1cSDK.META_REFERRER
            java.lang.String r4 = "Referrer collection disallowed by missing content providers."
            r5 = 0
            r6 = 4
            r7 = 0
            com.appsflyer.internal.AFg1gSDK.d$default(r2, r3, r4, r5, r6, r7)
            return r1
        Lb2:
            r12 = 1
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFj1zSDK.AFAdRevenueData(android.content.Context):boolean");
    }

    private static boolean component2(Context context) {
        return context.getPackageManager().resolveContentProvider("com.facebook.lite.provider.InstallReferrerProvider", 0) != null;
    }

    private final boolean getCurrencyIso4217Code(Context context) {
        int i = AFa1vSDK.getMonetizationNetwork[this.getCurrencyIso4217Code.ordinal()];
        if (i == 1) {
            return getMediationNetwork(context);
        }
        if (i == 2) {
            return getMonetizationNetwork(context);
        }
        if (i == 3) {
            return component2(context);
        }
        throw new NoWhenBranchMatchedException();
    }

    private static boolean getMediationNetwork(Context context) {
        return context.getPackageManager().resolveContentProvider("com.facebook.katana.provider.InstallReferrerProvider", 0) != null;
    }

    private static boolean getMonetizationNetwork(Context context) {
        return context.getPackageManager().resolveContentProvider("com.instagram.contentprovider.InstallReferrerProvider", 0) != null;
    }

    @Override // com.appsflyer.internal.AFj1qSDK
    @SuppressLint({"NewApi"})
    public final void getRevenue(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "");
        if (AFAdRevenueData(context)) {
            this.getMonetizationNetwork.execute(new g(4, this, context));
        } else {
            this.component3.run();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:27:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x00e9 A[Catch: all -> 0x006b, TRY_LEAVE, TryCatch #4 {all -> 0x006b, blocks: (B:9:0x004c, B:11:0x0052, B:28:0x00e9, B:14:0x0072, B:16:0x0083, B:17:0x0088, B:18:0x0089, B:20:0x008f, B:21:0x00a7, B:22:0x00b7, B:24:0x00bd, B:25:0x00d5), top: B:100:0x0045 }] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0210 A[PHI: r25
  0x0210: PHI (r25v2 android.content.ContentProviderClient) = 
  (r25v1 android.content.ContentProviderClient)
  (r25v3 android.content.ContentProviderClient)
  (r25v3 android.content.ContentProviderClient)
 binds: [B:83:0x0257, B:71:0x020e, B:76:0x0225] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0222  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0254  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void getMonetizationNetwork(com.appsflyer.internal.AFj1zSDK r31, android.content.Context r32) {
        /*
            Method dump skipped, instructions count: 623
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFj1zSDK.getMonetizationNetwork(com.appsflyer.internal.AFj1zSDK, android.content.Context):void");
    }
}
