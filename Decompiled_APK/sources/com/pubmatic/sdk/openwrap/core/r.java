package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public class r extends com.pubmatic.sdk.common.base.f {

    @NonNull
    private final com.pubmatic.sdk.common.base.m a;
    private com.pubmatic.sdk.common.base.h b;
    private com.pubmatic.sdk.common.base.e c;
    private com.pubmatic.sdk.common.models.f d;

    public class a implements com.pubmatic.sdk.common.base.k {
        private a() {
        }

        @Override // com.pubmatic.sdk.common.base.k
        public void onError(@NonNull com.pubmatic.sdk.common.h hVar) {
            r.this.a(hVar);
        }

        @Override // com.pubmatic.sdk.common.base.k
        public void onSuccess(@NonNull com.pubmatic.sdk.common.models.a aVar) {
            POBLog.debug("POBManager", "Ready to share Wrapper bid", new Object[0]);
            if (r.this.b != null) {
                r.this.b.setAdResponse(aVar);
            }
            if (((com.pubmatic.sdk.common.base.f) r.this).bidderListener != null) {
                ((com.pubmatic.sdk.common.base.f) r.this).bidderListener.onBidsFetched(r.this, aVar);
            }
        }
    }

    @Deprecated
    public r(@NonNull com.pubmatic.sdk.common.base.m mVar) {
        this.a = mVar;
        mVar.setListener(new a());
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void destroy() {
        this.bidderListener = null;
        this.a.cancel();
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public com.pubmatic.sdk.common.models.a getAdResponse() {
        com.pubmatic.sdk.common.base.h hVar = this.b;
        if (hVar != null) {
            return hVar.getAdResponse();
        }
        return null;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    @NonNull
    public Map<String, com.pubmatic.sdk.common.base.h> getBidderResults() {
        HashMap map = new HashMap();
        com.pubmatic.sdk.common.base.h hVar = this.b;
        if (hVar != null) {
            hVar.setNetworkResult(this.a.getNetworkResult());
            map.put(getIdentifier(), this.b);
        }
        return map;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void requestBid() {
        this.b = new com.pubmatic.sdk.common.base.h();
        if (b()) {
            this.a.requestAd();
        } else {
            a(new com.pubmatic.sdk.common.h(1012, "Ad request not allowed for device's current country"));
        }
    }

    @Override // com.pubmatic.sdk.common.base.f
    public void setCountryFilterConfig(com.pubmatic.sdk.common.base.e eVar) {
        this.c = eVar;
    }

    private com.pubmatic.sdk.common.base.n b(@NonNull Context context, @NonNull v vVar) {
        w wVar = new w(vVar, com.pubmatic.sdk.common.i.getSdkConfig().isRequestSecureCreative() ? "https://ow.pubmatic.com/openrtb/2.5" : "http://ow.pubmatic.com/openrtb/2.5", context);
        wVar.setAppInfo(com.pubmatic.sdk.common.i.getAppInfo(context.getApplicationContext()));
        wVar.setDeviceInfo(com.pubmatic.sdk.common.i.getDeviceInfo(context.getApplicationContext()));
        wVar.setLocationDetector(com.pubmatic.sdk.common.i.getLocationDetector(context.getApplicationContext()));
        return wVar;
    }

    private com.pubmatic.sdk.common.base.p c() {
        return new com.pubmatic.sdk.openwrap.core.internal.b();
    }

    private com.pubmatic.sdk.common.base.m a(@NonNull Context context, @NonNull v vVar) {
        return new com.pubmatic.sdk.common.base.m(b(context, vVar), c(), a(), a(context));
    }

    public r(@NonNull Context context, @NonNull com.pubmatic.sdk.common.base.m mVar) {
        this.a = mVar;
        mVar.setListener(new a());
        this.d = com.pubmatic.sdk.common.i.getDeviceInfo(context);
    }

    private com.pubmatic.sdk.common.base.b a() {
        return new com.pubmatic.sdk.openwrap.core.internal.a();
    }

    public r(@NonNull v vVar, @NonNull Context context) {
        com.pubmatic.sdk.common.base.m mVarA = a(context, vVar);
        this.a = mVarA;
        mVarA.setListener(new a());
        this.d = com.pubmatic.sdk.common.i.getDeviceInfo(context);
    }

    @NonNull
    private com.pubmatic.sdk.common.network.g a(@NonNull Context context) {
        return com.pubmatic.sdk.common.i.getNetworkHandler(context.getApplicationContext());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull com.pubmatic.sdk.common.h hVar) {
        com.pubmatic.sdk.common.base.h hVar2 = this.b;
        if (hVar2 != null) {
            hVar2.setError(hVar);
        }
        com.pubmatic.sdk.common.base.g gVar = this.bidderListener;
        if (gVar != null) {
            gVar.onBidsFailed(this, hVar);
        }
    }

    private boolean b() {
        String iSOAlpha2CountryCode;
        if (this.c != null) {
            com.pubmatic.sdk.common.models.f fVar = this.d;
            if (fVar != null) {
                iSOAlpha2CountryCode = fVar.getISOAlpha2CountryCode();
                Locale locale = Locale.ENGLISH;
                POBLog.debug("POBManager", AbstractC0147y.d("Device country code is ", iSOAlpha2CountryCode), new Object[0]);
            } else {
                iSOAlpha2CountryCode = null;
            }
            if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(iSOAlpha2CountryCode)) {
                String countryFilteringMode = this.c.getCountryFilteringMode();
                Set<String> filteringCountries = this.c.getFilteringCountries();
                if (filteringCountries != null && filteringCountries.size() > 0) {
                    if (com.pubmatic.sdk.common.models.i.COUNTRY_FILTERING_ALLOW_MODE.equals(countryFilteringMode)) {
                        return filteringCountries.contains(iSOAlpha2CountryCode);
                    }
                    if (com.pubmatic.sdk.common.models.i.COUNTRY_FILTERING_BLOCK_MODE.equals(countryFilteringMode)) {
                        return !filteringCountries.contains(iSOAlpha2CountryCode);
                    }
                }
            }
        }
        return true;
    }
}
