package com.braze.support;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.braze.AbstractC1475a;
import com.braze.AbstractC1484j;
import com.braze.C1480f;
import com.braze.storage.e0;
import com.braze.support.BrazeLogger;
import java.math.BigDecimal;
import java.util.Locale;
import java.util.Set;
import kotlin.Metadata;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes.dex */
public final class ValidationUtils {
    private static final Regex EMAIL_ADDRESS_REGEX;
    private static final Regex ENDPOINT_REGEX;
    public static final ValidationUtils INSTANCE = new ValidationUtils();
    private static final Regex PHONE_NUMBER_REGEX;
    private static final Set<String> VALID_CURRENCY_CODES;

    static {
        String[] elements = {"AED", "AFN", "ALL", "AMD", "ANG", "AOA", "ARS", "AUD", "AWG", "AZN", "BAM", "BBD", "BDT", "BGN", "BHD", "BIF", "BMD", "BND", "BOB", "BRL", "BSD", "BTC", "BTN", "BWP", "BYR", "BZD", "CAD", "CDF", "CHF", "CLF", "CLP", "CNY", "COP", "CRC", "CUC", "CUP", "CVE", "CZK", "DJF", "DKK", "DOP", "DZD", "EEK", "EGP", "ERN", "ETB", "EUR", "FJD", "FKP", "GBP", "GEL", "GGP", "GHS", "GIP", "GMD", "GNF", "GTQ", "GYD", "HKD", "HNL", "HRK", "HTG", "HUF", "IDR", "ILS", "IMP", "INR", "IQD", "IRR", "ISK", "JEP", "JMD", "JOD", "JPY", "KES", "KGS", "KHR", "KMF", "KPW", "KRW", "KWD", "KYD", "KZT", "LAK", "LBP", "LKR", "LRD", "LSL", "LTL", "LVL", "LYD", "MAD", "MDL", "MGA", "MKD", "MMK", "MNT", "MOP", "MRO", "MTL", "MUR", "MVR", "MWK", "MXN", "MYR", "MZN", "NAD", "NGN", "NIO", "NOK", "NPR", "NZD", "OMR", "PAB", "PEN", "PGK", "PHP", "PKR", "PLN", "PYG", "QAR", "RON", "RSD", "RUB", "RWF", "SAR", "SBD", "SCR", "SDG", "SEK", "SGD", "SHP", "SLL", "SOS", "SRD", "STD", "SVC", "SYP", "SZL", "THB", "TJS", "TMT", "TND", "TOP", "TRY", "TTD", "TWD", "TZS", "UAH", "UGX", "USD", "UYU", "UZS", "VEF", "VND", "VUV", "WST", "XAF", "XAG", "XAU", "XCD", "XDR", "XOF", "XPD", "XPF", "XPT", "YER", "ZAR", "ZMK", "ZMW", "ZWL"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        VALID_CURRENCY_CODES = C4933y.T(elements);
        EMAIL_ADDRESS_REGEX = new Regex(".+@.+\\..+");
        PHONE_NUMBER_REGEX = new Regex("^[0-9 .\\(\\)\\+\\-]+$");
        ENDPOINT_REGEX = new Regex("rest\\.[a-z]+-[0-9]+\\.braze\\.");
    }

    private ValidationUtils() {
    }

    public static final String ensureBrazeFieldLength(String str) {
        if (str == null || StringsKt.O(str)) {
            return "";
        }
        J j = new J();
        String string = StringsKt.g0(str).toString();
        j.a = string;
        if (string.length() > 255) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C1480f(j, 8), 6, (Object) null);
            String strSubstring = ((String) j.a).substring(0, 255);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            j.a = strSubstring;
        }
        return (String) j.a;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String ensureBrazeFieldLength$lambda$0(J j) {
        return "Provided string field is too long [" + ((String) j.a).length() + "]. The max length is 255, truncating provided field.";
    }

    public static final boolean isInvalidCustomEndpoint$android_sdk_base_release(String str) {
        if (str != null) {
            return ENDPOINT_REGEX.a(str);
        }
        return false;
    }

    public static final boolean isValidEmailAddress(String str) {
        if (str == null || str.length() == 0 || str.length() > 255) {
            return false;
        }
        return EMAIL_ADDRESS_REGEX.e(str);
    }

    public static final boolean isValidLineId(String str) {
        return str != null && str.length() <= 33;
    }

    public static final boolean isValidLocation(double d, double d2) {
        return d < 90.0d && d > -90.0d && d2 < 180.0d && d2 > -180.0d;
    }

    public static final boolean isValidLogCustomEventInput(String str, e0 serverConfigStorageProvider) {
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        if (str == null || StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(7), 6, (Object) null);
            return false;
        }
        if (!serverConfigStorageProvider.f().contains(str)) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str, 0), 6, (Object) null);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogCustomEventInput$lambda$8() {
        return "The custom event name cannot be null or contain only whitespaces. Invalid custom event.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogCustomEventInput$lambda$9(String str) {
        return AbstractC1475a.a("The custom event is a blocklisted custom event: ", str, ". Invalid custom event.");
    }

    public static final boolean isValidLogPurchaseInput(String str, String str2, BigDecimal bigDecimal, int i, e0 serverConfigStorageProvider) {
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        if (str == null || StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(6), 6, (Object) null);
            return false;
        }
        if (serverConfigStorageProvider.g().contains(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str, 1), 6, (Object) null);
            return false;
        }
        if (str2 == null || StringsKt.O(str2)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(5), 6, (Object) null);
            return false;
        }
        Set<String> set = VALID_CURRENCY_CODES;
        String string = StringsKt.g0(str2).toString();
        Locale US = Locale.US;
        Intrinsics.checkNotNullExpressionValue(US, "US");
        String upperCase = string.toUpperCase(US);
        Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
        if (!set.contains(upperCase)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str2, 2), 6, (Object) null);
            return false;
        }
        if (bigDecimal == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(10), 6, (Object) null);
            return false;
        }
        if (i <= 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 14), 6, (Object) null);
            return false;
        }
        if (i <= 100) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 15), 6, (Object) null);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$1() {
        return "The productId is empty, not logging in-app purchase to Braze.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$2(String str) {
        return AbstractC1484j.a("The productId is a blocklisted productId: ", str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$3() {
        return "The currencyCode is empty. Expected one of " + VALID_CURRENCY_CODES;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$4(String str) {
        StringBuilder sbY = android.support.v4.media.session.a.y("The currencyCode ", str, " is invalid. Expected one of ");
        sbY.append(VALID_CURRENCY_CODES);
        return sbY.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$5() {
        return "The price is null.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$6(int i) {
        return AbstractC0147y.c(i, "The requested purchase quantity of ", " is less than one. Invalid purchase");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidLogPurchaseInput$lambda$7(int i) {
        return AbstractC0147y.c(i, "The requested purchase quantity of ", " is greater than the maximum of 100");
    }

    public static final boolean isValidPhoneNumber(String str) {
        return str != null && PHONE_NUMBER_REGEX.e(str);
    }

    public static final boolean isValidPushStoryClickInput(String str, String str2) {
        if (str == null || StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(9), 6, (Object) null);
            return false;
        }
        if (str2 != null && !StringsKt.O(str2)) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) INSTANCE, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(8), 6, (Object) null);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidPushStoryClickInput$lambda$10() {
        return "Campaign ID cannot be null or blank";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String isValidPushStoryClickInput$lambda$11() {
        return "Push story page ID cannot be null or blank";
    }
}
