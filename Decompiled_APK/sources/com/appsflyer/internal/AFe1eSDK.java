package com.appsflyer.internal;

import android.content.Context;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFb1vSDK;
import com.comscore.streaming.ContentType;
import com.google.android.gms.common.GoogleApiAvailability;
import com.samsung.android.game.cloudgame.dev.sdk.CloudDevCallback;
import com.samsung.android.game.cloudgame.dev.sdk.CloudDevSdk;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFe1eSDK extends AFe1sSDK<AFh1oSDK> {

    @NotNull
    public static final AFa1tSDK AFa1tSDK = new AFa1tSDK(null);

    @NotNull
    private final AFc1iSDK areAllFieldsValid;

    @NotNull
    private final AFh1oSDK component1;

    @NotNull
    private final AFc1kSDK component2;

    @NotNull
    private final AFc1pSDK component3;

    @NotNull
    private final kotlin.k component4;

    @NotNull
    private final kotlin.k equals;

    @Metadata
    /* renamed from: com.appsflyer.internal.AFe1eSDK$3, reason: invalid class name */
    public static final class AnonymousClass3 extends r implements Function0<Boolean> {
        public AnonymousClass3() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Boolean invoke() {
            return Boolean.valueOf(Boolean.parseBoolean(AFe1eSDK.this.component3.getCurrencyIso4217Code("com.appsflyer.enable_instant_plays")));
        }
    }

    @Metadata
    /* renamed from: com.appsflyer.internal.AFe1eSDK$4, reason: invalid class name */
    public static final class AnonymousClass4 extends r implements Function0<Long> {
        public AnonymousClass4() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Long invoke() {
            Long lF0;
            String currencyIso4217Code = AFe1eSDK.this.component3.getCurrencyIso4217Code("com.appsflyer.fetch_ids.timeout");
            return Long.valueOf((currencyIso4217Code == null || (lF0 = StringsKt.f0(currencyIso4217Code)) == null) ? 1000L : lF0.longValue());
        }
    }

    @Metadata
    public static final class AFa1tSDK {
        private AFa1tSDK() {
        }

        public /* synthetic */ AFa1tSDK(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }
    }

    @Metadata
    public static final class AFa1ySDK {
        private String advertisingId;
        private boolean advertisingIdWithGps;

        @NotNull
        private final StringBuilder gaidError;
        private Boolean isLimitAdTrackingEnabled;

        public AFa1ySDK() {
            this(null, null, false, null, 15, null);
        }

        public static /* synthetic */ AFa1ySDK copy$default(AFa1ySDK aFa1ySDK, String str, Boolean bool, boolean z, StringBuilder sb, int i, Object obj) {
            if ((i & 1) != 0) {
                str = aFa1ySDK.advertisingId;
            }
            if ((i & 2) != 0) {
                bool = aFa1ySDK.isLimitAdTrackingEnabled;
            }
            if ((i & 4) != 0) {
                z = aFa1ySDK.advertisingIdWithGps;
            }
            if ((i & 8) != 0) {
                sb = aFa1ySDK.gaidError;
            }
            return aFa1ySDK.copy(str, bool, z, sb);
        }

        public final String component1() {
            return this.advertisingId;
        }

        public final Boolean component2() {
            return this.isLimitAdTrackingEnabled;
        }

        public final boolean component3() {
            return this.advertisingIdWithGps;
        }

        @NotNull
        public final StringBuilder component4() {
            return this.gaidError;
        }

        @NotNull
        public final AFa1ySDK copy(String str, Boolean bool, boolean z, @NotNull StringBuilder gaidError) {
            Intrinsics.checkNotNullParameter(gaidError, "gaidError");
            return new AFa1ySDK(str, bool, z, gaidError);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof AFa1ySDK)) {
                return false;
            }
            AFa1ySDK aFa1ySDK = (AFa1ySDK) obj;
            return Intrinsics.b(this.advertisingId, aFa1ySDK.advertisingId) && Intrinsics.b(this.isLimitAdTrackingEnabled, aFa1ySDK.isLimitAdTrackingEnabled) && this.advertisingIdWithGps == aFa1ySDK.advertisingIdWithGps && Intrinsics.b(this.gaidError, aFa1ySDK.gaidError);
        }

        public final String getAdvertisingId() {
            return this.advertisingId;
        }

        public final boolean getAdvertisingIdWithGps() {
            return this.advertisingIdWithGps;
        }

        @NotNull
        public final StringBuilder getGaidError() {
            return this.gaidError;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public final int hashCode() {
            String str = this.advertisingId;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Boolean bool = this.isLimitAdTrackingEnabled;
            int iHashCode2 = (iHashCode + (bool != null ? bool.hashCode() : 0)) * 31;
            boolean z = this.advertisingIdWithGps;
            int i = z;
            if (z != 0) {
                i = 1;
            }
            return this.gaidError.hashCode() + ((iHashCode2 + i) * 31);
        }

        public final Boolean isLimitAdTrackingEnabled() {
            return this.isLimitAdTrackingEnabled;
        }

        public final void setAdvertisingId(String str) {
            this.advertisingId = str;
        }

        public final void setAdvertisingIdWithGps(boolean z) {
            this.advertisingIdWithGps = z;
        }

        public final void setLimitAdTrackingEnabled(Boolean bool) {
            this.isLimitAdTrackingEnabled = bool;
        }

        @NotNull
        public final String toString() {
            return "FetchGaidData(advertisingId=" + this.advertisingId + ", isLimitAdTrackingEnabled=" + this.isLimitAdTrackingEnabled + ", advertisingIdWithGps=" + this.advertisingIdWithGps + ", gaidError=" + ((Object) this.gaidError) + ")";
        }

        public AFa1ySDK(String str, Boolean bool, boolean z, @NotNull StringBuilder gaidError) {
            Intrinsics.checkNotNullParameter(gaidError, "gaidError");
            this.advertisingId = str;
            this.isLimitAdTrackingEnabled = bool;
            this.advertisingIdWithGps = z;
            this.gaidError = gaidError;
        }

        public /* synthetic */ AFa1ySDK(String str, Boolean bool, boolean z, StringBuilder sb, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : bool, (i & 4) != 0 ? false : z, (i & 8) != 0 ? new StringBuilder() : sb);
        }
    }

    @Metadata
    public static final class AFa1zSDK implements CloudDevCallback {
        final /* synthetic */ AFa1ySDK $fetchGaidData;
        final /* synthetic */ CountDownLatch $latch;

        public AFa1zSDK(AFa1ySDK aFa1ySDK, CountDownLatch countDownLatch) {
            this.$fetchGaidData = aFa1ySDK;
            this.$latch = countDownLatch;
        }

        public final void onError(@NotNull String reason) {
            Intrinsics.checkNotNullParameter(reason, "reason");
            AFg1gSDK.w$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, AbstractC0147y.d("Could not fetch GAID using CloudDevSdk: ", reason), false, 4, null);
            StringBuilder gaidError = this.$fetchGaidData.getGaidError();
            gaidError.append(reason);
            gaidError.append(" |");
            this.$latch.countDown();
        }

        public final void onSuccess(@NotNull Map<String, String> kinds) {
            Intrinsics.checkNotNullParameter(kinds, "kinds");
            AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, "CloudDevCallback received onSuccess", false, 4, null);
            this.$fetchGaidData.setAdvertisingId(kinds.get("gaid"));
            this.$latch.countDown();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AFe1eSDK(@NotNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.FETCH_ADVERTISING_ID, new AFe1mSDK[0], "FetchAdvertisingIdTask");
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        AFc1iSDK aFc1iSDKAFInAppEventType = aFc1dSDK.AFInAppEventType();
        Intrinsics.checkNotNullExpressionValue(aFc1iSDKAFInAppEventType, "");
        this.areAllFieldsValid = aFc1iSDKAFInAppEventType;
        AFc1pSDK revenue = aFc1dSDK.getRevenue();
        Intrinsics.checkNotNullExpressionValue(revenue, "");
        this.component3 = revenue;
        AFc1kSDK aFc1kSDKAfInfoLog = aFc1dSDK.afInfoLog();
        Intrinsics.checkNotNullExpressionValue(aFc1kSDKAfInfoLog, "");
        this.component2 = aFc1kSDKAfInfoLog;
        this.component1 = new AFh1oSDK(null, null, null, null, null, null, null, null, 255, null);
        this.component4 = kotlin.l.b(new AnonymousClass4());
        this.equals = kotlin.l.b(new AnonymousClass3());
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x004d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final boolean AFAdRevenueData(int r14) {
        /*
            r13 = this;
            com.appsflyer.AFLogger r0 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r1 = com.appsflyer.internal.AFg1cSDK.ADVERTISING_ID
            r4 = 4
            r5 = 0
            java.lang.String r2 = "Trying to fetch GAID..."
            r3 = 0
            com.appsflyer.internal.AFg1gSDK.i$default(r0, r1, r2, r3, r4, r5)
            com.appsflyer.internal.AFe1eSDK$AFa1ySDK r6 = new com.appsflyer.internal.AFe1eSDK$AFa1ySDK
            r11 = 15
            r12 = 0
            r7 = 0
            r8 = 0
            r9 = 0
            r10 = 0
            r6.<init>(r7, r8, r9, r10, r11, r12)
            com.appsflyer.internal.AFc1iSDK r0 = r13.areAllFieldsValid
            android.content.Context r0 = r0.getMonetizationNetwork
            kotlin.jvm.internal.Intrinsics.d(r0)
            int r0 = getCurrencyIso4217Code(r0)
            com.appsflyer.internal.AFc1iSDK r1 = r13.areAllFieldsValid
            android.content.Context r1 = r1.getMonetizationNetwork
            kotlin.jvm.internal.Intrinsics.d(r1)
            boolean r1 = r13.getCurrencyIso4217Code(r1, r6)
            r2 = 0
            r3 = 1
            if (r1 != 0) goto L83
            com.appsflyer.AppsFlyerProperties r1 = com.appsflyer.AppsFlyerProperties.getInstance()
            java.lang.String r4 = "enableGpsFallback"
            boolean r1 = r1.getBoolean(r4, r3)
            if (r1 == 0) goto L4d
            com.appsflyer.internal.AFc1iSDK r1 = r13.areAllFieldsValid
            android.content.Context r1 = r1.getMonetizationNetwork
            kotlin.jvm.internal.Intrinsics.d(r1)
            boolean r1 = r13.AFAdRevenueData(r1, r6)
            if (r1 == 0) goto L4d
            r1 = r3
            goto L4e
        L4d:
            r1 = r2
        L4e:
            java.lang.StringBuilder r4 = r6.getGaidError()
            java.lang.String r4 = r4.toString()
            if (r4 == 0) goto L7b
            boolean r5 = kotlin.text.StringsKt.O(r4)
            if (r5 == 0) goto L5f
            goto L7b
        L5f:
            java.lang.CharSequence r4 = kotlin.text.StringsKt.g0(r4)
            java.lang.String r4 = r4.toString()
            java.lang.StringBuilder r5 = new java.lang.StringBuilder
            r5.<init>()
            r5.append(r0)
            java.lang.String r0 = ": "
            r5.append(r0)
            r5.append(r4)
            java.lang.String r4 = r5.toString()
        L7b:
            com.appsflyer.internal.AFh1oSDK r0 = r13.component1
            AFAdRevenueData(r0, r4)
            if (r1 != 0) goto L83
            return r2
        L83:
            com.appsflyer.internal.AFh1oSDK r0 = r13.component1
            java.lang.String r1 = r6.getAdvertisingId()
            r0.AFAdRevenueData = r1
            java.lang.Boolean r1 = r6.isLimitAdTrackingEnabled()
            r0.getRevenue = r1
            java.lang.Boolean r1 = r6.isLimitAdTrackingEnabled()
            if (r1 == 0) goto La1
            boolean r1 = r1.booleanValue()
            r1 = r1 ^ r3
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r1)
            goto La2
        La1:
            r1 = 0
        La2:
            r0.getMonetizationNetwork = r1
            boolean r1 = r6.getAdvertisingIdWithGps()
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r1)
            r0.getMediationNetwork = r1
            java.lang.Boolean r1 = java.lang.Boolean.FALSE
            r0.getCurrencyIso4217Code = r1
            r1 = 2
            if (r14 == r1) goto Lb6
            r2 = r3
        Lb6:
            java.lang.Boolean r14 = java.lang.Boolean.valueOf(r2)
            r0.component2 = r14
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFe1eSDK.AFAdRevenueData(int):boolean");
    }

    private final boolean component1() {
        return ((Boolean) this.equals.getValue()).booleanValue();
    }

    private static boolean component3() {
        try {
            Class.forName("com.samsung.android.game.cloudgame.dev.sdk.CloudDevSdk");
            return true;
        } catch (Throwable th) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, th instanceof ClassNotFoundException ? "CloudDevSdk not found" : AbstractC0147y.d("Unexpected exception while checking if running in cloud environment: ", th.getMessage()), th, true, false, false, false, ContentType.LONG_FORM_ON_DEMAND, null);
            return false;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0045 A[LOOP:0: B:3:0x0005->B:15:0x0045, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0048 A[EDGE_INSN: B:19:0x0048->B:16:0x0048 BREAK  A[LOOP:0: B:3:0x0005->B:15:0x0045], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final boolean equals() {
        /*
            r17 = this;
            r0 = r17
            r1 = 2
            r2 = 0
            r3 = r2
        L5:
            if (r1 <= 0) goto L48
            boolean r3 = r0.component1()
            r4 = 1
            if (r3 == 0) goto L22
            boolean r3 = r0.getMediationNetwork(r1)
            if (r3 == 0) goto L22
            com.appsflyer.AFLogger r5 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r6 = com.appsflyer.internal.AFg1cSDK.ADVERTISING_ID
            r9 = 4
            r10 = 0
            java.lang.String r7 = "GAID fetched using Samsung Cloud dev SDK"
            r8 = 0
            com.appsflyer.internal.AFg1gSDK.v$default(r5, r6, r7, r8, r9, r10)
        L20:
            r3 = r4
            goto L43
        L22:
            boolean r3 = r0.AFAdRevenueData(r1)
            if (r3 == 0) goto L35
            com.appsflyer.AFLogger r5 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r6 = com.appsflyer.internal.AFg1cSDK.ADVERTISING_ID
            r9 = 4
            r10 = 0
            java.lang.String r7 = "GAID fetched using GMS"
            r8 = 0
            com.appsflyer.internal.AFg1gSDK.v$default(r5, r6, r7, r8, r9, r10)
            goto L20
        L35:
            com.appsflyer.AFLogger r11 = com.appsflyer.AFLogger.INSTANCE
            com.appsflyer.internal.AFg1cSDK r12 = com.appsflyer.internal.AFg1cSDK.ADVERTISING_ID
            r15 = 4
            r16 = 0
            java.lang.String r13 = "Failed to fetch GAID"
            r14 = 0
            com.appsflyer.internal.AFg1gSDK.v$default(r11, r12, r13, r14, r15, r16)
            r3 = r2
        L43:
            if (r3 != 0) goto L48
            int r1 = r1 + (-1)
            goto L5
        L48:
            com.appsflyer.internal.AFc1kSDK r1 = r0.component2
            com.appsflyer.internal.AFh1oSDK r2 = r0.component1
            r1.component3 = r2
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFe1eSDK.equals():boolean");
    }

    private static int getCurrencyIso4217Code(Context context) {
        try {
            return GoogleApiAvailability.d.c(context, com.google.android.gms.common.c.a);
        } catch (Throwable th) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, "isGooglePlayServicesAvailable error", th, false, false, false, false, 96, null);
            return -1;
        }
    }

    private final boolean getMonetizationNetwork(int i) {
        String str;
        AFLogger aFLogger = AFLogger.INSTANCE;
        AFg1cSDK aFg1cSDK = AFg1cSDK.ADVERTISING_ID;
        AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Trying to fetch GAID using Samsung Cloud Dev...", false, 4, null);
        if (component3()) {
            CloudDevSdk cloudDevSdk = CloudDevSdk.INSTANCE;
            Context context = this.areAllFieldsValid.getMonetizationNetwork;
            Intrinsics.d(context);
            if (cloudDevSdk.isCloudEnvironment(context)) {
                AFa1ySDK aFa1ySDK = new AFa1ySDK(null, null, false, null, 15, null);
                CountDownLatch countDownLatch = new CountDownLatch(1);
                try {
                    CloudDevSdk cloudDevSdk2 = CloudDevSdk.INSTANCE;
                    Context context2 = this.areAllFieldsValid.getMonetizationNetwork;
                    Intrinsics.d(context2);
                    cloudDevSdk2.request(context2, A.b("gaid"), new AFa1zSDK(aFa1ySDK, countDownLatch));
                    countDownLatch.await(((Number) this.component4.getValue()).longValue(), TimeUnit.MILLISECONDS);
                } catch (Throwable th) {
                    try {
                        if (th instanceof InterruptedException) {
                            str = "Fetch GAID using Samsung Cloud Dev interrupted or reached to timeout";
                        } else if (th instanceof ClassNotFoundException) {
                            str = "CloudDevSdk not found";
                        } else {
                            str = "Unexpected exception while fetching GAID using Samsung Cloud Dev " + th.getMessage();
                        }
                        AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, str, th, true, false, false, false, ContentType.LONG_FORM_ON_DEMAND, null);
                        StringBuilder gaidError = aFa1ySDK.getGaidError();
                        gaidError.append(th.getClass().getSimpleName());
                        gaidError.append(" |");
                        if (aFa1ySDK.getGaidError().length() > 0) {
                        }
                    } catch (Throwable th2) {
                        if (aFa1ySDK.getGaidError().length() > 0) {
                            AFAdRevenueData(this.component1, aFa1ySDK.getGaidError().toString());
                        }
                        throw th2;
                    }
                }
                if (aFa1ySDK.getGaidError().length() > 0) {
                    AFAdRevenueData(this.component1, aFa1ySDK.getGaidError().toString());
                }
                String advertisingId = aFa1ySDK.getAdvertisingId();
                if (advertisingId == null || advertisingId.length() == 0) {
                    return false;
                }
                AFh1oSDK aFh1oSDK = this.component1;
                aFh1oSDK.AFAdRevenueData = aFa1ySDK.getAdvertisingId();
                Boolean bool = Boolean.FALSE;
                aFh1oSDK.getRevenue = bool;
                Boolean bool2 = Boolean.TRUE;
                aFh1oSDK.getMonetizationNetwork = bool2;
                aFh1oSDK.getMediationNetwork = bool;
                aFh1oSDK.getCurrencyIso4217Code = bool2;
                aFh1oSDK.component2 = Boolean.valueOf(i != 2);
                return true;
            }
        }
        AFg1gSDK.i$default(aFLogger, aFg1cSDK, "Not running in Samsung Cloud Environment. Try using GMS...", false, 4, null);
        return false;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    private final boolean getMediationNetwork(int i) {
        return getMonetizationNetwork(i);
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    @NotNull
    public final AFe1rSDK getCurrencyIso4217Code() {
        AFe1rSDK aFe1rSDK;
        if (this.component2.getMonetizationNetwork()) {
            AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, "QUEUE: Advertising ID collection is disabled. Skipping fetching... ", false, 4, null);
            return AFe1rSDK.FAILURE;
        }
        long jCurrentTimeMillis = System.currentTimeMillis();
        Boolean boolValueOf = Boolean.valueOf(equals());
        Boolean bool = Boolean.FALSE;
        if (B.j(boolValueOf, bool, bool).contains(Boolean.TRUE)) {
            aFe1rSDK = AFe1rSDK.SUCCESS;
        } else {
            aFe1rSDK = AFe1rSDK.FAILURE;
        }
        AFc1kSDK aFc1kSDK = this.component2;
        AFd1hSDK aFd1hSDK = new AFd1hSDK(System.currentTimeMillis() - jCurrentTimeMillis);
        AFg1gSDK.v$default(AFLogger.INSTANCE, AFg1cSDK.ADVERTISING_ID, d0.o(aFd1hSDK.getRevenue, "QUEUE: FetchAdvertisingIdTask: took ", "ms"), false, 4, null);
        aFc1kSDK.getRevenue(aFd1hSDK);
        return aFe1rSDK;
    }

    private final boolean getCurrencyIso4217Code(Context context, AFa1ySDK aFa1ySDK) throws IllegalStateException {
        try {
            com.google.android.gms.ads.identifier.a aVarA = com.google.android.gms.ads.identifier.b.a(context);
            aFa1ySDK.setAdvertisingId(aVarA.a);
            aFa1ySDK.setLimitAdTrackingEnabled(Boolean.valueOf(aVarA.b));
            aFa1ySDK.setAdvertisingIdWithGps(true);
            String advertisingId = aFa1ySDK.getAdvertisingId();
            if (advertisingId == null || advertisingId.length() == 0) {
                aFa1ySDK.getGaidError().append("emptyOrNull |");
            }
            if (Unit.a != null) {
                return true;
            }
            aFa1ySDK.getGaidError().append("gpsAdInfo-null |");
            throw new IllegalStateException("GpsAdIndo is null");
        } catch (Throwable th) {
            AFLogger aFLogger = AFLogger.INSTANCE;
            AFg1cSDK aFg1cSDK = AFg1cSDK.ADVERTISING_ID;
            AFg1gSDK.e$default(aFLogger, aFg1cSDK, AbstractC0147y.d("Google Play Services is missing ", th.getMessage()), th, false, false, false, false, 88, null);
            StringBuilder gaidError = aFa1ySDK.getGaidError();
            gaidError.append(th.getClass().getSimpleName());
            gaidError.append(" |");
            AFg1gSDK.i$default(aFLogger, aFg1cSDK, "WARNING: Google Play Services is missing.", false, 4, null);
            return false;
        }
    }

    private final boolean AFAdRevenueData(Context context, AFa1ySDK aFa1ySDK) throws IllegalStateException {
        try {
            AFb1vSDK.AFa1vSDK aFa1vSDKAFAdRevenueData = AFb1vSDK.AFAdRevenueData(context);
            aFa1ySDK.setAdvertisingId(aFa1vSDKAFAdRevenueData.AFAdRevenueData);
            aFa1ySDK.setLimitAdTrackingEnabled(Boolean.valueOf(aFa1vSDKAFAdRevenueData.getCurrencyIso4217Code()));
            String advertisingId = aFa1ySDK.getAdvertisingId();
            if (advertisingId == null || advertisingId.length() == 0) {
                aFa1ySDK.getGaidError().append("emptyOrNull (bypass) |");
            }
            if (Unit.a != null) {
                return true;
            }
            aFa1ySDK.getGaidError().append("gpsAdInfo-null (bypass) |");
            throw new IllegalStateException("GpsAdInfo is null (bypass)");
        } catch (Throwable th) {
            AFLogger aFLogger = AFLogger.INSTANCE;
            AFg1cSDK aFg1cSDK = AFg1cSDK.ADVERTISING_ID;
            AFg1gSDK.e$default(aFLogger, aFg1cSDK, AbstractC0147y.d("Failed to fetch GAID: ", th.getMessage()), th, true, false, false, false, 64, null);
            StringBuilder gaidError = aFa1ySDK.getGaidError();
            gaidError.append(th.getClass().getSimpleName());
            gaidError.append(" |");
            String localizedMessage = th.getLocalizedMessage();
            if (localizedMessage == null) {
                localizedMessage = th.toString();
            }
            AFg1gSDK.i$default(aFLogger, aFg1cSDK, localizedMessage, false, 4, null);
            return false;
        }
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return ((Number) this.component4.getValue()).longValue();
    }

    private static void AFAdRevenueData(AFh1oSDK aFh1oSDK, String str) {
        String strL;
        if (str == null) {
            return;
        }
        String str2 = aFh1oSDK.areAllFieldsValid;
        if (str2 != null && (strL = android.support.v4.media.session.a.l(str2, " | ", str)) != null) {
            str = strL;
        }
        aFh1oSDK.areAllFieldsValid = str;
    }
}
