package com.appsflyer.share;

import android.content.Context;
import android.support.v4.media.session.a;
import com.amazon.device.ads.DtbConstants;
import com.appsflyer.AFInAppEventParameterName;
import com.appsflyer.AFLogger;
import com.appsflyer.AppsFlyerLib;
import com.appsflyer.AppsFlyerProperties;
import com.appsflyer.CreateOneLinkHttpTask;
import com.appsflyer.internal.AFa1tSDK;
import com.appsflyer.internal.AFc1dSDK;
import com.appsflyer.internal.AFe1kSDK;
import com.appsflyer.internal.AFe1lSDK;
import com.appsflyer.internal.AFe1lSDK.AnonymousClass5;
import com.appsflyer.internal.AFj1bSDK;
import com.appsflyer.internal.AFk1wSDK;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/* loaded from: classes.dex */
public class LinkGenerator {
    private String AFAdRevenueData;
    private String areAllFieldsValid;
    private String component1;
    private String component2;
    private String component3;
    private String component4;
    private final Map<String, String> equals = new HashMap();
    String getCurrencyIso4217Code;
    private final String getMediationNetwork;
    String getMonetizationNetwork;
    private String getRevenue;
    private String hashCode;
    private String toString;

    public interface ResponseListener {
        void onResponse(String str);

        void onResponseError(String str);
    }

    public LinkGenerator(String str) {
        this.getMediationNetwork = str;
    }

    private Map<String, String> getMediationNetwork() {
        HashMap map = new HashMap();
        map.put("pid", this.getMediationNetwork);
        String str = this.areAllFieldsValid;
        if (str != null) {
            map.put("af_referrer_uid", str);
        }
        String str2 = this.getRevenue;
        if (str2 != null) {
            map.put(AFInAppEventParameterName.AF_CHANNEL, str2);
        }
        String str3 = this.component1;
        if (str3 != null) {
            map.put("af_referrer_customer_id", str3);
        }
        String str4 = this.AFAdRevenueData;
        if (str4 != null) {
            map.put("c", str4);
        }
        String str5 = this.component4;
        if (str5 != null) {
            map.put("af_referrer_name", str5);
        }
        String str6 = this.component2;
        if (str6 != null) {
            map.put("af_referrer_image_url", str6);
        }
        if (this.toString != null) {
            StringBuilder sb = new StringBuilder();
            sb.append(this.toString);
            String str7 = this.component3;
            if (str7 != null) {
                this.component3 = str7.replaceFirst("^[/]", "");
                sb.append(this.toString.endsWith("/") ? "" : "/");
                sb.append(this.component3);
            }
            map.put("af_dp", sb.toString());
        }
        for (Map.Entry<String, String> entry : this.equals.entrySet()) {
            map.put(entry.getKey(), entry.getValue());
        }
        return AFj1bSDK.getRevenue(map);
    }

    public LinkGenerator addParameter(String str, String str2) {
        this.equals.put(str, str2);
        return this;
    }

    public LinkGenerator addParameters(Map<String, String> map) {
        if (map != null) {
            this.equals.putAll(map);
        }
        return this;
    }

    public String generateLink() {
        StringBuilder sb = new StringBuilder();
        String str = this.getCurrencyIso4217Code;
        if (str == null || !str.startsWith("http")) {
            sb.append(String.format(AFk1wSDK.getMediationNetwork, AppsFlyerLib.getInstance().getHostPrefix(), ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getHostName()));
        } else {
            sb.append(this.getCurrencyIso4217Code);
        }
        if (this.getMonetizationNetwork != null) {
            sb.append('/');
            sb.append(this.getMonetizationNetwork);
        }
        Map<String, String> mediationNetwork = getMediationNetwork();
        StringBuilder sb2 = new StringBuilder();
        for (Map.Entry<String, String> entry : mediationNetwork.entrySet()) {
            if (sb2.length() == 0) {
                sb2.append('?');
            } else {
                sb2.append('&');
            }
            sb2.append(entry.getKey());
            sb2.append('=');
            sb2.append(entry.getValue());
        }
        sb.append(sb2.toString());
        return sb.toString();
    }

    public String getBrandDomain() {
        return this.hashCode;
    }

    public String getCampaign() {
        return this.AFAdRevenueData;
    }

    public String getChannel() {
        return this.getRevenue;
    }

    public String getMediaSource() {
        return this.getMediationNetwork;
    }

    public Map<String, String> getUserParams() {
        return new HashMap(this.equals);
    }

    public LinkGenerator setBaseDeeplink(String str) {
        this.toString = str;
        return this;
    }

    public LinkGenerator setBaseURL(String str, String str2, String str3) {
        if (str == null || str.length() <= 0) {
            this.getCurrencyIso4217Code = a.m(DtbConstants.HTTPS, a.l(AppsFlyerLib.getInstance().getHostPrefix(), "app.", ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getHostName()), "/", str3);
            return this;
        }
        if (str2 == null || str2.length() < 5) {
            str2 = "go.onelink.me";
        }
        this.getCurrencyIso4217Code = a.m(DtbConstants.HTTPS, str2, "/", str);
        return this;
    }

    public LinkGenerator setBrandDomain(String str) {
        this.hashCode = str;
        return this;
    }

    public LinkGenerator setCampaign(String str) {
        this.AFAdRevenueData = str;
        return this;
    }

    public LinkGenerator setChannel(String str) {
        this.getRevenue = str;
        return this;
    }

    public LinkGenerator setDeeplinkPath(String str) {
        this.component3 = str;
        return this;
    }

    public LinkGenerator setReferrerCustomerId(String str) {
        this.component1 = str;
        return this;
    }

    public LinkGenerator setReferrerImageURL(String str) {
        this.component2 = str;
        return this;
    }

    public LinkGenerator setReferrerName(String str) {
        this.component4 = str;
        return this;
    }

    public LinkGenerator setReferrerUID(String str) {
        this.areAllFieldsValid = str;
        return this;
    }

    public void generateLink(Context context, ResponseListener responseListener) {
        String string = AppsFlyerProperties.getInstance().getString(AppsFlyerProperties.ONELINK_ID);
        String str = this.hashCode;
        Map<String, String> mediationNetwork = getMediationNetwork();
        if (AppsFlyerProperties.getInstance().getBoolean(AppsFlyerProperties.AF_WAITFOR_CUSTOMERID, false)) {
            AFLogger.afInfoLog("CustomerUserId not set, generate User Invite Link is disabled", true);
            return;
        }
        ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).getMediationNetwork(context);
        AFc1dSDK aFc1dSDKAFAdRevenueData = ((AFa1tSDK) AFa1tSDK.getMonetizationNetwork(new Object[0], -631580017, 631580017, (int) System.currentTimeMillis())).AFAdRevenueData();
        AFe1kSDK aFe1kSDK = new AFe1kSDK(aFc1dSDKAFAdRevenueData, UUID.randomUUID(), string, mediationNetwork, str, responseListener, this);
        AFe1lSDK aFe1lSDKCopydefault = aFc1dSDKAFAdRevenueData.copydefault();
        aFe1lSDKCopydefault.getRevenue.execute(aFe1lSDKCopydefault.new AnonymousClass5(aFe1kSDK));
    }

    @Deprecated
    public void generateLink(Context context, final CreateOneLinkHttpTask.ResponseListener responseListener) {
        generateLink(context, new ResponseListener() { // from class: com.appsflyer.share.LinkGenerator.2
            @Override // com.appsflyer.share.LinkGenerator.ResponseListener
            public final void onResponse(String str) {
                responseListener.onResponse(str);
            }

            @Override // com.appsflyer.share.LinkGenerator.ResponseListener
            public final void onResponseError(String str) {
                responseListener.onResponseError(str);
            }
        });
    }
}
