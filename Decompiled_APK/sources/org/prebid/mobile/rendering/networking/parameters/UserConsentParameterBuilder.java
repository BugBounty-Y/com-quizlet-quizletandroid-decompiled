package org.prebid.mobile.rendering.networking.parameters;

import com.amazon.device.ads.DtbConstants;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import java.util.ArrayList;
import java.util.Collection;
import org.json.JSONArray;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.models.openrtb.BidRequest;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Ext;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Regs;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.User;
import org.prebid.mobile.rendering.sdk.ManagersResolver;
import org.prebid.mobile.rendering.sdk.deviceData.managers.UserConsentManager;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class UserConsentParameterBuilder extends ParameterBuilder {
    public final UserConsentManager a = ManagersResolver.a().d;

    @Override // org.prebid.mobile.rendering.networking.parameters.ParameterBuilder
    public final void a(AdRequestInput adRequestInput) {
        BidRequest bidRequest = adRequestInput.a;
        UserConsentManager userConsentManager = this.a;
        int i = userConsentManager.b;
        Boolean bool = i == 0 ? Boolean.FALSE : i == 1 ? Boolean.TRUE : null;
        if (bool != null) {
            boolean zBooleanValue = bool.booleanValue();
            Regs regsC = bidRequest.c();
            if (regsC.a == null) {
                regsC.a = new Ext();
            }
            regsC.a.a.put("gdpr", Integer.valueOf(zBooleanValue ? 1 : 0));
            String str = userConsentManager.c;
            if (!Utils.b(str)) {
                if (bidRequest.f == null) {
                    bidRequest.f = new User();
                }
                User user = bidRequest.f;
                if (user.b == null) {
                    user.b = new Ext();
                }
                user.b.a.put(OTVendorUtils.CONSENT_TYPE, str);
            }
        }
        String str2 = userConsentManager.e;
        if (!Utils.b(str2)) {
            Regs regsC2 = bidRequest.c();
            if (regsC2.a == null) {
                regsC2.a = new Ext();
            }
            regsC2.a.a.put(DtbConstants.APS_ADMOB_CONST_CCPA_US_PRIVACY, str2);
        }
        String str3 = userConsentManager.f;
        if (str3 != null) {
            bidRequest.c().b = str3;
        }
        String str4 = userConsentManager.g;
        if (str4 != null) {
            Regs regsC3 = bidRequest.c();
            regsC3.getClass();
            if (str4.isEmpty()) {
                return;
            }
            try {
                String[] strArrSplit = str4.split("_");
                ArrayList arrayList = new ArrayList(strArrSplit.length);
                for (String str5 : strArrSplit) {
                    if (!str5.isEmpty()) {
                        arrayList.add(Integer.valueOf(str5));
                    }
                }
                if (arrayList.isEmpty()) {
                    return;
                }
                regsC3.c = new JSONArray((Collection) arrayList);
            } catch (Exception unused) {
                LogUtil.a("Can't parse GPP Sid. Current value: ".concat(str4));
            }
        }
    }
}
