package com.appsflyer.internal;

import android.adservices.measurement.MeasurementManager;
import android.annotation.SuppressLint;
import android.content.Context;
import android.net.Uri;
import android.os.OutcomeReceiver;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFe1tSDK;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFf1zSDK extends AFe1sSDK<Unit> {

    @NotNull
    public AFe1tSDK areAllFieldsValid;

    @NotNull
    public Executor component1;

    @NotNull
    public AFc1iSDK component2;

    @NotNull
    public AFc1pSDK component3;

    @NotNull
    public AFg1qSDK component4;

    @NotNull
    public Function1<AFe1rSDK, Unit> copydefault;

    @NotNull
    public AFf1gSDK equals;

    public static final class AFa1vSDK implements OutcomeReceiver {
        private /* synthetic */ CountDownLatch AFAdRevenueData;
        private /* synthetic */ J getCurrencyIso4217Code;
        private /* synthetic */ AFf1zSDK getMonetizationNetwork;

        public AFa1vSDK(J j, CountDownLatch countDownLatch, AFf1zSDK aFf1zSDK) {
            this.getCurrencyIso4217Code = j;
            this.AFAdRevenueData = countDownLatch;
            this.getMonetizationNetwork = aFf1zSDK;
        }

        public final /* synthetic */ void onError(Throwable th) {
            Exception exc = (Exception) th;
            Intrinsics.checkNotNullParameter(exc, "");
            AFf1zSDK.getMediationNetwork(exc);
            this.AFAdRevenueData.countDown();
        }

        public final void onResult(@NotNull Object obj) {
            Intrinsics.checkNotNullParameter(obj, "");
            this.getCurrencyIso4217Code.a = AFe1rSDK.SUCCESS;
            AFLogger.INSTANCE.d(AFg1cSDK.PRIVACY_SANDBOX, "Privacy Sandbox trigger has been registered successfully. ", true);
            this.AFAdRevenueData.countDown();
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public AFf1zSDK(@NotNull AFe1tSDK aFe1tSDK, @NotNull Executor executor, @NotNull AFc1pSDK aFc1pSDK, @NotNull AFc1iSDK aFc1iSDK, @NotNull AFg1qSDK aFg1qSDK, @NotNull AFf1gSDK aFf1gSDK, @NotNull Function1<? super AFe1rSDK, Unit> function1) {
        super(AFe1mSDK.REGISTER_TRIGGER, new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, null);
        Intrinsics.checkNotNullParameter(aFe1tSDK, "");
        Intrinsics.checkNotNullParameter(executor, "");
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFc1iSDK, "");
        Intrinsics.checkNotNullParameter(aFg1qSDK, "");
        Intrinsics.checkNotNullParameter(aFf1gSDK, "");
        Intrinsics.checkNotNullParameter(function1, "");
        this.areAllFieldsValid = aFe1tSDK;
        this.component1 = executor;
        this.component3 = aFc1pSDK;
        this.component2 = aFc1iSDK;
        this.component4 = aFg1qSDK;
        this.equals = aFf1gSDK;
        this.copydefault = function1;
        if (aFe1tSDK instanceof AFe1tSDK.AFa1tSDK) {
            this.getCurrencyIso4217Code.add(AFe1mSDK.CONVERSION);
        }
        if (this.areAllFieldsValid instanceof AFe1tSDK.AFa1uSDK) {
            this.AFAdRevenueData.add(AFe1mSDK.CONVERSION);
        }
        if (this.areAllFieldsValid instanceof AFe1tSDK.AFa1vSDK) {
            this.AFAdRevenueData.add(AFe1mSDK.INAPP);
        }
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    @SuppressLint({"NewApi"})
    @NotNull
    public final AFe1rSDK getCurrencyIso4217Code() {
        MeasurementManager measurementManagerK;
        J j = new J();
        j.a = AFe1rSDK.FAILURE;
        CountDownLatch countDownLatch = new CountDownLatch(1);
        try {
            Context context = this.component2.getMonetizationNetwork;
            if (context != null && (measurementManagerK = androidx.credentials.i.k(context.getSystemService(androidx.credentials.i.t()))) != null) {
                new AFj1fSDK(this.component3, null, 2, null);
                Uri.Builder builderBuildUpon = Uri.parse(AFj1fSDK.getCurrencyIso4217Code()).buildUpon();
                String strAFAdRevenueData = this.component3.AFAdRevenueData();
                if (strAFAdRevenueData == null) {
                    strAFAdRevenueData = "";
                }
                Pair pair = new Pair("event_name", this.areAllFieldsValid.getMediationNetwork);
                Pair pair2 = new Pair("app_id", this.component3.getRevenue.getMonetizationNetwork.getPackageName());
                Context context2 = this.component3.getRevenue.getMonetizationNetwork;
                LinkedHashMap linkedHashMapG = V.g(pair, pair2, new Pair("app_version", AFj1iSDK.getMediationNetwork(context2, context2.getPackageName())), new Pair("sdk_version", AFc1pSDK.getMonetizationNetwork()), new Pair("api_version", AFc1pSDK.getMediationNetwork()), new Pair("timestamp", String.valueOf(this.component4.AFAdRevenueData())), new Pair("request_id", AFc1pSDK.getRevenue()), new Pair("gaid", strAFAdRevenueData));
                String revenue = AFb1iSDK.getRevenue(this.component3.getMonetizationNetwork);
                if (revenue != null) {
                    linkedHashMapG.put("appsflyer_id", revenue);
                }
                Long currencyIso4217Code = this.component4.getCurrencyIso4217Code();
                if (currencyIso4217Code != null) {
                    linkedHashMapG.put("install_time", String.valueOf(currencyIso4217Code.longValue()));
                }
                AFe1tSDK aFe1tSDK = this.areAllFieldsValid;
                if (aFe1tSDK instanceof AFe1tSDK.AFa1vSDK) {
                    Float f = ((AFe1tSDK.AFa1vSDK) aFe1tSDK).getRevenue;
                    if (f != null) {
                        linkedHashMapG.put("event_revenue", String.valueOf(f.floatValue()));
                    }
                    Integer num = ((AFe1tSDK.AFa1vSDK) this.areAllFieldsValid).getCurrencyIso4217Code;
                    if (num != null) {
                        linkedHashMapG.put("event_count", String.valueOf(num.intValue()));
                    }
                }
                for (Map.Entry entry : linkedHashMapG.entrySet()) {
                    builderBuildUpon.appendQueryParameter((String) entry.getKey(), (String) entry.getValue());
                }
                Uri uriBuild = builderBuildUpon.build();
                Intrinsics.checkNotNullExpressionValue(uriBuild, "");
                measurementManagerK.registerTrigger(uriBuild, this.component1, new AFa1vSDK(j, countDownLatch, this));
            }
            countDownLatch.await(4L, TimeUnit.SECONDS);
        } catch (InterruptedException unused) {
            j.a = AFe1rSDK.TIMEOUT;
        } catch (Throwable th) {
            AFLogger.INSTANCE.e(AFg1cSDK.PRIVACY_SANDBOX, AbstractC0147y.d("Error occurred: ", th.getMessage()), th, false, false, false, true);
        }
        return (AFe1rSDK) j.a;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return 20000L;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final void getRevenue() {
        super.getRevenue();
        AFe1rSDK aFe1rSDK = this.getMediationNetwork;
        if (aFe1rSDK != null) {
            this.copydefault.invoke(aFe1rSDK);
        }
    }

    public static final /* synthetic */ void getMediationNetwork(Throwable th) {
        AFLogger.INSTANCE.e(AFg1cSDK.PRIVACY_SANDBOX, AbstractC0147y.d("Error occurred: ", th.getMessage()), th, false, false, false, true);
    }
}
