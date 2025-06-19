package com.appsflyer.internal;

import android.util.Base64;
import com.appsflyer.AFLogger;
import java.util.Arrays;
import java.util.Scanner;

/* loaded from: classes.dex */
public final class AFc1rSDK {
    String AFAdRevenueData;
    private byte[] getCurrencyIso4217Code;
    public String getMediationNetwork;
    public AFe1mSDK getMonetizationNetwork;
    public String getRevenue;

    public AFc1rSDK(String str, byte[] bArr, String str2, AFe1mSDK aFe1mSDK) {
        this.getRevenue = str;
        this.getCurrencyIso4217Code = bArr;
        this.AFAdRevenueData = str2;
        this.getMonetizationNetwork = aFe1mSDK;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && AFc1rSDK.class == obj.getClass()) {
            AFc1rSDK aFc1rSDK = (AFc1rSDK) obj;
            String str = this.AFAdRevenueData;
            if (str == null ? aFc1rSDK.AFAdRevenueData != null : !str.equals(aFc1rSDK.AFAdRevenueData)) {
                return false;
            }
            if (!Arrays.equals(this.getCurrencyIso4217Code, aFc1rSDK.getCurrencyIso4217Code)) {
                return false;
            }
            String str2 = this.getRevenue;
            if (str2 == null ? aFc1rSDK.getRevenue != null : !str2.equals(aFc1rSDK.getRevenue)) {
                return false;
            }
            String str3 = this.getMediationNetwork;
            if (str3 == null ? aFc1rSDK.getMediationNetwork != null : !str3.equals(aFc1rSDK.getMediationNetwork)) {
                return false;
            }
            if (this.getMonetizationNetwork == aFc1rSDK.getMonetizationNetwork) {
                return true;
            }
        }
        return false;
    }

    public final byte[] getMediationNetwork() {
        return this.getCurrencyIso4217Code;
    }

    public final int hashCode() {
        String str = this.AFAdRevenueData;
        int iHashCode = (Arrays.hashCode(this.getCurrencyIso4217Code) + ((str != null ? str.hashCode() : 0) * 31)) * 31;
        String str2 = this.getRevenue;
        int iHashCode2 = (iHashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.getMediationNetwork;
        int iHashCode3 = (iHashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31;
        AFe1mSDK aFe1mSDK = this.getMonetizationNetwork;
        return iHashCode3 + (aFe1mSDK != null ? aFe1mSDK.hashCode() : 0);
    }

    public AFc1rSDK(char[] cArr) {
        Scanner scanner = new Scanner(new String(cArr));
        while (scanner.hasNextLine()) {
            String strNextLine = scanner.nextLine();
            if (strNextLine.startsWith("url=")) {
                this.getRevenue = strNextLine.substring(4).trim();
            } else if (strNextLine.startsWith("version=")) {
                this.AFAdRevenueData = strNextLine.substring(8).trim();
            } else if (strNextLine.startsWith("data=")) {
                this.getCurrencyIso4217Code = Base64.decode(strNextLine.substring(5).trim(), 2);
            } else if (strNextLine.startsWith("type=")) {
                String strTrim = strNextLine.substring(5).trim();
                try {
                    this.getMonetizationNetwork = AFe1mSDK.valueOf(strTrim);
                } catch (Exception e) {
                    AFLogger.afErrorLog("CACHE: Unknown task type: ".concat(String.valueOf(strTrim)), e);
                }
            }
        }
        scanner.close();
    }
}
