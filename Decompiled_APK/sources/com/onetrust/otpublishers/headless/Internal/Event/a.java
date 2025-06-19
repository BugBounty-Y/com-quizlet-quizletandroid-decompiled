package com.onetrust.otpublishers.headless.Internal.Event;

import androidx.compose.foundation.lazy.grid.m;
import com.comscore.streaming.EventType;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTEventListener;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class a {
    public final HashSet a = new HashSet();

    public final void a(m mVar) {
        HashSet hashSet = this.a;
        int size = hashSet.size();
        if (size <= 0) {
            OTLogger.c("EventListenerSetter", 3, "Empty callback set. No oneTrustEventListener callback.");
            return;
        }
        OTLogger.c("EventListenerSetter", 4, "Sending oneTrustDataEventListener callback. oneTrustEventListener size = " + size);
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            OTEventListener oTEventListener = (OTEventListener) it2.next();
            String str = (String) mVar.d;
            switch (mVar.a) {
                case 1:
                    oTEventListener.onShowBanner((OTUIDisplayReason) mVar.f);
                    break;
                case 2:
                    oTEventListener.onHideBanner();
                    break;
                case 3:
                    oTEventListener.onBannerClickedAcceptAll();
                    break;
                case 4:
                    oTEventListener.onBannerClickedRejectAll();
                    break;
                case 5:
                    oTEventListener.onShowPreferenceCenter((OTUIDisplayReason) mVar.f);
                    break;
                case 6:
                    oTEventListener.onHidePreferenceCenter();
                    break;
                case 7:
                    oTEventListener.onPreferenceCenterPurposeConsentChanged((String) mVar.c, mVar.b);
                    break;
                case 8:
                    oTEventListener.onPreferenceCenterAcceptAll();
                    break;
                case 9:
                    oTEventListener.onPreferenceCenterRejectAll();
                    break;
                case 10:
                    oTEventListener.onPreferenceCenterConfirmChoices();
                    break;
                case 11:
                    oTEventListener.onPreferenceCenterPurposeLegitimateInterestChanged((String) mVar.c, mVar.b);
                    break;
                case 12:
                    oTEventListener.onShowVendorList();
                    break;
                case 13:
                    oTEventListener.onHideVendorList();
                    break;
                case 14:
                    oTEventListener.onVendorConfirmChoices();
                    break;
                case 15:
                    if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.e)) {
                        oTEventListener.onVendorListVendorConsentChanged((String) mVar.e, (String) mVar.c, mVar.b);
                        break;
                    } else {
                        oTEventListener.onVendorListVendorConsentChanged((String) mVar.c, mVar.b);
                        break;
                    }
                case 16:
                    oTEventListener.onVendorListVendorLegitimateInterestChanged((String) mVar.c, mVar.b);
                    break;
                case 17:
                    oTEventListener.allSDKViewsDismissed(str);
                    break;
                case 18:
                    oTEventListener.onSDKNoAction(str);
                    break;
                case 19:
                    oTEventListener.onVendorListAcceptAll();
                    break;
                case 20:
                    oTEventListener.onVendorListRejectAll();
                    break;
                case EventType.VIDEO /* 24 */:
                    oTEventListener.onSdkListSdkConsentChanged((String) mVar.c, mVar.b);
                    break;
                case EventType.SUBS /* 25 */:
                    oTEventListener.onShowSdkList();
                    break;
                case EventType.CDN /* 26 */:
                    oTEventListener.onHideSdkList();
                    break;
            }
        }
    }
}
