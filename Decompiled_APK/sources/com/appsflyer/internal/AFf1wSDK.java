package com.appsflyer.internal;

import android.media.AudioTrack;
import android.view.View;
import com.appsflyer.AFLogger;
import com.comscore.streaming.ContentType;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReasonCode;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFf1wSDK extends AFf1uSDK {
    private static int $10 = 0;
    private static int $11 = 1;
    private static int AFKeystoreWrapper = 1;
    private static int registerClient;

    @NotNull
    private final AFc1pSDK equals;

    @NotNull
    private final AFi1fSDK hashCode;
    private static char[] AFInAppEventParameterName = {10791, 10809, 10763, 10805, 10784, 10788, 10801, 10813, 10802};
    private static char AFLogger = 8141;

    public /* synthetic */ AFf1wSDK(AFi1fSDK aFi1fSDK, AFc1pSDK aFc1pSDK, AFc1dSDK aFc1dSDK, AFh1eSDK aFh1eSDK, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(aFi1fSDK, aFc1pSDK, aFc1dSDK, (i & 8) != 0 ? new AFh1eSDK() : aFh1eSDK);
    }

    private static void a(byte b, String str, int i, Object[] objArr) {
        int i2;
        char[] charArray = str != null ? str.toCharArray() : str;
        AFk1mSDK aFk1mSDK = new AFk1mSDK();
        char[] cArr = AFInAppEventParameterName;
        if (cArr != null) {
            $11 = ($10 + ContentType.USER_GENERATED_SHORT_FORM_ON_DEMAND) % 128;
            int length = cArr.length;
            char[] cArr2 = new char[length];
            for (int i3 = 0; i3 < length; i3++) {
                cArr2[i3] = (char) (cArr[i3] ^ (-374623853307093042L));
            }
            cArr = cArr2;
        }
        char c = (char) ((-374623853307093042L) ^ AFLogger);
        char[] cArr3 = new char[i];
        if (i % 2 != 0) {
            $10 = ($11 + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_MOVED_REGION) % 128;
            i2 = i - 1;
            cArr3[i2] = (char) (charArray[i2] - b);
        } else {
            i2 = i;
        }
        if (i2 > 1) {
            int i4 = $11 + 67;
            $10 = i4 % 128;
            int i5 = i4 % 2;
            aFk1mSDK.AFAdRevenueData = 0;
            while (true) {
                int i6 = aFk1mSDK.AFAdRevenueData;
                if (i6 >= i2) {
                    break;
                }
                int i7 = $11;
                int i8 = (i7 + 57) % 128;
                $10 = i8;
                char c2 = charArray[i6];
                aFk1mSDK.getMonetizationNetwork = c2;
                char c3 = charArray[i6 + 1];
                aFk1mSDK.getCurrencyIso4217Code = c3;
                if (c2 == c3) {
                    int i9 = i7 + 81;
                    $10 = i9 % 128;
                    if (i9 % 2 != 0) {
                        cArr3[i6] = (char) (c2 >>> b);
                        cArr3[i6 >> 1] = (char) (c3 << b);
                    } else {
                        cArr3[i6] = (char) (c2 - b);
                        cArr3[i6 + 1] = (char) (c3 - b);
                    }
                } else {
                    int i10 = c2 / c;
                    aFk1mSDK.getMediationNetwork = i10;
                    int i11 = c2 % c;
                    aFk1mSDK.component1 = i11;
                    int i12 = c3 / c;
                    aFk1mSDK.getRevenue = i12;
                    int i13 = c3 % c;
                    aFk1mSDK.component2 = i13;
                    if (i11 == i13) {
                        int i14 = (i8 + 3) % 128;
                        $11 = i14;
                        int i15 = ((i10 + c) - 1) % c;
                        aFk1mSDK.getMediationNetwork = i15;
                        int i16 = ((i12 + c) - 1) % c;
                        aFk1mSDK.getRevenue = i16;
                        cArr3[i6] = cArr[(i15 * c) + i11];
                        cArr3[i6 + 1] = cArr[(i16 * c) + i13];
                        $10 = (i14 + 19) % 128;
                    } else if (i10 == i12) {
                        int i17 = ((i11 + c) - 1) % c;
                        aFk1mSDK.component1 = i17;
                        int i18 = ((i13 + c) - 1) % c;
                        aFk1mSDK.component2 = i18;
                        cArr3[i6] = cArr[(i10 * c) + i17];
                        cArr3[i6 + 1] = cArr[(i12 * c) + i18];
                    } else {
                        cArr3[i6] = cArr[(i10 * c) + i13];
                        cArr3[i6 + 1] = cArr[(i12 * c) + i11];
                    }
                }
                aFk1mSDK.AFAdRevenueData = i6 + 2;
            }
        }
        for (int i19 = 0; i19 < i; i19++) {
            cArr3[i19] = (char) (cArr3[i19] ^ 13722);
        }
        objArr[0] = new String(cArr3);
    }

    private final void areAllFieldsValid(AFh1rSDK aFh1rSDK) {
        try {
            Map<String, ?> map = (Map) getRevenue(new Object[]{this}, -846475554, 846475554, System.identityHashCode(this));
            if (map != null) {
                int i = AFKeystoreWrapper + 97;
                registerClient = i % 128;
                if (i % 2 != 0) {
                    aFh1rSDK.getMediationNetwork(map);
                    throw null;
                }
                aFh1rSDK.getMediationNetwork(map);
            }
            if (this.hashCode.AFAdRevenueData()) {
                return;
            }
            registerClient = (AFKeystoreWrapper + 3) % 128;
            Map<String, Object> mapComponent1 = AFf1rSDK.component1(aFh1rSDK);
            Intrinsics.checkNotNullExpressionValue(mapComponent1, "");
            mapComponent1.put("pia_disabled", Boolean.TRUE);
        } catch (Throwable th) {
            AFg1gSDK.e$default(AFLogger.INSTANCE, AFg1cSDK.PLAY_INTEGRITY_API, "Error while adding PIA data to payload", th, true, false, false, false, 96, null);
        }
    }

    private final Map<String, Object> copy() {
        return (Map) getRevenue(new Object[]{this}, -846475554, 846475554, System.identityHashCode(this));
    }

    private static /* synthetic */ Object getCurrencyIso4217Code(Object[] objArr) {
        AFf1wSDK aFf1wSDK = (AFf1wSDK) objArr[0];
        registerClient = (AFKeystoreWrapper + 75) % 128;
        AFi1hSDK currencyIso4217Code = aFf1wSDK.hashCode.getCurrencyIso4217Code();
        if (currencyIso4217Code == null) {
            return null;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        LinkedHashMap linkedHashMap2 = new LinkedHashMap();
        linkedHashMap2.put("pia_timestamp", Long.valueOf(currencyIso4217Code.AFAdRevenueData));
        linkedHashMap2.put("ttr_millis", Long.valueOf(currencyIso4217Code.getRevenue));
        String str = currencyIso4217Code.getCurrencyIso4217Code;
        if (str != null) {
            int i = AFKeystoreWrapper + 117;
            registerClient = i % 128;
            if (i % 2 != 0) {
                linkedHashMap2.put("pia_token", str);
                throw null;
            }
            linkedHashMap2.put("pia_token", str);
        }
        String str2 = currencyIso4217Code.getMonetizationNetwork;
        if (str2 != null) {
            registerClient = (AFKeystoreWrapper + 55) % 128;
            linkedHashMap2.put("error_code", str2);
            registerClient = (AFKeystoreWrapper + 19) % 128;
        }
        linkedHashMap.put("pia", linkedHashMap2);
        return linkedHashMap;
    }

    public static /* synthetic */ Object getRevenue(Object[] objArr, int i, int i2, int i3) {
        return getCurrencyIso4217Code(objArr);
    }

    @Override // com.appsflyer.internal.AFf1uSDK
    public final void AFAdRevenueData(int i) {
        int i2 = registerClient + 69;
        AFKeystoreWrapper = i2 % 128;
        if (i2 % 2 == 0) {
            throw null;
        }
    }

    @Override // com.appsflyer.internal.AFf1rSDK, com.appsflyer.internal.AFe1dSDK
    public final boolean copydefault() {
        int i = (registerClient + 31) % 128;
        AFKeystoreWrapper = i;
        registerClient = (i + 67) % 128;
        return false;
    }

    @Override // com.appsflyer.internal.AFf1uSDK, com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        registerClient = (AFKeystoreWrapper + 97) % 128;
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        AFKeystoreWrapper = (registerClient + 63) % 128;
        long millis = TimeUnit.MINUTES.toMillis(1L);
        AFKeystoreWrapper = (registerClient + 85) % 128;
        return millis;
    }

    @Override // com.appsflyer.internal.AFf1uSDK, com.appsflyer.internal.AFf1rSDK
    public final void AFAdRevenueData(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        Map<String, Object> map = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map, "");
        Object[] objArr = new Object[1];
        a((byte) (View.resolveSize(0, 0) + OTUIDisplayReasonCode.UIShownCode.BANNER_SHOWN_SYNC_FAILED), "\u0005\u0006\u0001\u0005\u0001\u0004\u0000\u0003\u0005\u0004\u0002\u0004", 13 - (AudioTrack.getMaxVolume() > DefinitionKt.NO_Float_VALUE ? 1 : (AudioTrack.getMaxVolume() == DefinitionKt.NO_Float_VALUE ? 0 : -1)), objArr);
        map.put(((String) objArr[0]).intern(), String.valueOf(new Date().getTime()));
        super.AFAdRevenueData(aFh1rSDK);
        areAllFieldsValid(aFh1rSDK);
        AFg1qSDK aFg1qSDK = this.toString;
        Map<String, Object> map2 = aFh1rSDK.AFAdRevenueData;
        Intrinsics.checkNotNullExpressionValue(map2, "");
        aFg1qSDK.getRevenue(map2, this.equals.getMonetizationNetwork.AFAdRevenueData("appsFlyerCount", 0), this.equals.getMonetizationNetwork.AFAdRevenueData("appsFlyerInAppEventCount", 0));
        int i = registerClient + 111;
        AFKeystoreWrapper = i % 128;
        if (i % 2 == 0) {
            throw null;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    private AFf1wSDK(@NotNull AFi1fSDK aFi1fSDK, @NotNull AFc1pSDK aFc1pSDK, @NotNull AFc1dSDK aFc1dSDK, @NotNull AFh1eSDK aFh1eSDK) {
        super(aFh1eSDK, aFc1dSDK);
        Intrinsics.checkNotNullParameter(aFi1fSDK, "");
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        Intrinsics.checkNotNullParameter(aFh1eSDK, "");
        this.hashCode = aFi1fSDK;
        this.equals = aFc1pSDK;
        this.getCurrencyIso4217Code.add(AFe1mSDK.CONVERSION);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AFf1wSDK(@NotNull AFi1fSDK aFi1fSDK, @NotNull AFc1pSDK aFc1pSDK, @NotNull AFc1dSDK aFc1dSDK) {
        this(aFi1fSDK, aFc1pSDK, aFc1dSDK, null, 8, null);
        Intrinsics.checkNotNullParameter(aFi1fSDK, "");
        Intrinsics.checkNotNullParameter(aFc1pSDK, "");
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
    }
}
