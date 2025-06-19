package com.appsflyer.internal;

import android.content.SharedPreferences;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.appsflyer.AFLogger;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class AFc1jSDK implements AFc1qSDK {

    @NotNull
    private final AFc1hSDK<SharedPreferences> getMediationNetwork;

    @NotNull
    private final kotlin.k getMonetizationNetwork;

    @Metadata
    /* renamed from: com.appsflyer.internal.AFc1jSDK$5, reason: invalid class name */
    public static final class AnonymousClass5 extends r implements Function0<SharedPreferences> {
        public AnonymousClass5() {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        /* renamed from: l_, reason: merged with bridge method [inline-methods] */
        public final SharedPreferences invoke() {
            return (SharedPreferences) AFc1jSDK.this.getMediationNetwork.getMonetizationNetwork.invoke();
        }
    }

    public AFc1jSDK(@NotNull AFc1hSDK<SharedPreferences> aFc1hSDK) {
        Intrinsics.checkNotNullParameter(aFc1hSDK, "");
        this.getMediationNetwork = aFc1hSDK;
        this.getMonetizationNetwork = kotlin.l.b(new AnonymousClass5());
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final void getCurrencyIso4217Code(String str, boolean z) {
        assistantMode.refactored.a.p((SharedPreferences) this.getMonetizationNetwork.getValue(), str, z);
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final void getMediationNetwork(String str, String str2) {
        ((SharedPreferences) this.getMonetizationNetwork.getValue()).edit().putString(str, str2).apply();
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final void getMonetizationNetwork(String str, long j) {
        ((SharedPreferences) this.getMonetizationNetwork.getValue()).edit().putLong(str, j).apply();
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final String AFAdRevenueData(String str, String str2) {
        try {
            return ((SharedPreferences) this.getMonetizationNetwork.getValue()).getString(str, str2);
        } catch (ClassCastException e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.PREFERENCES, AbstractC0147y.d("Unexpected data type found for key ", str), e, false, false, false, false, 120, null);
            return str2;
        }
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final boolean getMediationNetwork(String str, boolean z) {
        try {
            return ((SharedPreferences) this.getMonetizationNetwork.getValue()).getBoolean(str, z);
        } catch (ClassCastException e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.PREFERENCES, AbstractC0147y.d("Unexpected data type found for key ", str), e, false, false, false, false, 120, null);
            return z;
        }
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final void getMonetizationNetwork(String str) {
        ((SharedPreferences) this.getMonetizationNetwork.getValue()).edit().remove(str).apply();
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final long getCurrencyIso4217Code(String str, long j) {
        try {
            return ((SharedPreferences) this.getMonetizationNetwork.getValue()).getLong(str, j);
        } catch (ClassCastException e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.PREFERENCES, AbstractC0147y.d("Unexpected data type found for key ", str), e, false, false, false, false, 120, null);
            return j;
        }
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final int AFAdRevenueData(String str, int i) {
        try {
            return ((SharedPreferences) this.getMonetizationNetwork.getValue()).getInt(str, i);
        } catch (ClassCastException e) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.PREFERENCES, AbstractC0147y.d("Unexpected data type found for key ", str), e, false, false, false, false, 120, null);
            return i;
        }
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final void getMediationNetwork(String str, int i) {
        ((SharedPreferences) this.getMonetizationNetwork.getValue()).edit().putInt(str, i).apply();
    }

    @Override // com.appsflyer.internal.AFc1qSDK
    public final boolean getMediationNetwork(String str) {
        return ((SharedPreferences) this.getMonetizationNetwork.getValue()).contains(str);
    }
}
