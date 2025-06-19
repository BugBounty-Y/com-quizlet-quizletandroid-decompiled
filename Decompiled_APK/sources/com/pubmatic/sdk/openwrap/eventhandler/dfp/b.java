package com.pubmatic.sdk.openwrap.eventhandler.dfp;

import android.content.Context;
import android.os.Trace;
import android.text.TextUtils;
import android.view.View;
import androidx.annotation.NonNull;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.h;
import com.pubmatic.sdk.common.base.j;
import com.pubmatic.sdk.common.f;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.k;
import com.pubmatic.sdk.common.utility.l;
import com.pubmatic.sdk.common.utility.o;
import java.util.Map;

/* loaded from: classes2.dex */
public class b extends com.pubmatic.sdk.openwrap.banner.a implements com.google.android.gms.ads.admanager.a {
    private com.pubmatic.sdk.openwrap.eventhandler.dfp.a a;
    private c b;
    private Boolean c;
    private boolean d;
    private l e;
    private AdManagerAdView f;
    private com.pubmatic.sdk.openwrap.banner.b g;
    private C0018b h;
    private final f[] i;
    private boolean j;

    public class a implements k {
        public a() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            b.this.c();
        }
    }

    static {
        POBLog.debug("DFPBannerEventHandler", "%s version is %s", b.class.getSimpleName(), "4.0.0");
    }

    public b(@NonNull Context context, @NonNull String str, @NonNull h... hVarArr) {
        AdManagerAdView adManagerAdViewA = a(context, str);
        this.f = adManagerAdViewA;
        adManagerAdViewA.setAdSizes(hVarArr);
        this.i = d.a(hVarArr);
    }

    @Override // com.pubmatic.sdk.openwrap.core.e
    public void destroy() {
        d();
        AdManagerAdView adManagerAdView = this.f;
        if (adManagerAdView != null) {
            adManagerAdView.destroy();
            this.f = null;
        }
        this.g = null;
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public View getAdServerView() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public f getAdSize() {
        AdManagerAdView adManagerAdView = this.f;
        if (adManagerAdView != null) {
            return d.a(adManagerAdView);
        }
        return null;
    }

    @Override // com.google.android.gms.ads.admanager.a
    public void onAppEvent(@NonNull String str, @NonNull String str2) {
        POBLog.info("DFPBannerEventHandler", "On app event received", new Object[0]);
        if (this.f != null) {
            POBLog.debug("DFPBannerEventHandler", "GAM Banner Ad size :" + this.f.getAdSize(), new Object[0]);
        }
        POBLog.debug("DFPBannerEventHandler", android.support.v4.media.session.a.m("GAM callback partner name: ", str, "bid id: ", str2), new Object[0]);
        if (TextUtils.equals(str, "pubmaticdm")) {
            Boolean bool = this.c;
            if (bool != null) {
                if (bool.booleanValue()) {
                    return;
                }
                a(new com.pubmatic.sdk.common.h(1010, "GAM ad server mismatched bid win signal"));
                return;
            }
            this.c = Boolean.TRUE;
            if (this.g != null) {
                POBLog.info("DFPBannerEventHandler", "OpenWrap Partner Won.", new Object[0]);
                Trace.endSection();
                this.g.onOpenWrapPartnerWin(str2);
                a();
            }
        }
    }

    @Override // com.pubmatic.sdk.openwrap.core.e
    public void requestAd(com.pubmatic.sdk.openwrap.core.f fVar) {
        j bidsProvider;
        Map<String, String> targetingInfo;
        if (this.f == null || this.g == null) {
            Trace.endSection();
            POBLog.warn("DFPBannerEventHandler", "%s has been destroyed, initialise it before calling requestAd().", "DFPBannerEventHandler");
            return;
        }
        this.d = false;
        this.j = false;
        AdManagerAdRequest.Builder builder = new AdManagerAdRequest.Builder();
        com.pubmatic.sdk.openwrap.eventhandler.dfp.a aVar = this.a;
        if (aVar != null) {
            ((com.google.firebase.tracing.a) aVar).configure(this.f, builder, fVar);
        }
        AdManagerAdView adManagerAdView = this.f;
        if (adManagerAdView == null || this.g == null) {
            POBLog.warn("DFPBannerEventHandler", "%s has been destroyed, initialise it before calling requestAd().", "DFPBannerEventHandler");
            Trace.endSection();
            return;
        }
        if (adManagerAdView.getAdListener() != this.h || this.f.getAppEventListener() != this) {
            POBLog.warn("DFPBannerEventHandler", "Do not set GAM listeners. These are used by DFPBannerEventHandler internally.", new Object[0]);
        }
        POBLog.debug("DFPBannerEventHandler", "GAM Banner Ad unit :" + this.f.getAdUnitId(), new Object[0]);
        if (fVar != null && (bidsProvider = this.g.getBidsProvider()) != null && (targetingInfo = bidsProvider.getTargetingInfo()) != null && !targetingInfo.isEmpty()) {
            this.d = true;
            for (Map.Entry<String, String> entry : targetingInfo.entrySet()) {
                builder.addCustomTargeting(entry.getKey(), entry.getValue());
                POBLog.debug("DFPBannerEventHandler", "Targeting param [" + entry.getKey() + "] = " + entry.getValue(), new Object[0]);
            }
        }
        this.c = null;
        AdManagerAdRequest adManagerAdRequestBuild = builder.build();
        POBLog.debug("DFPBannerEventHandler", "Targeting sent in ad server request: " + adManagerAdRequestBuild.getCustomTargeting(), new Object[0]);
        Trace.beginSection("POB DFP Request Ad Banner");
        this.f.loadAd(adManagerAdRequestBuild);
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public f[] requestedAdSizes() {
        return this.i;
    }

    public void setAppEventListener(c cVar) {
    }

    public void setConfigListener(com.pubmatic.sdk.openwrap.eventhandler.dfp.a aVar) {
        this.a = aVar;
    }

    @Override // com.pubmatic.sdk.openwrap.banner.a
    public void setEventListener(com.pubmatic.sdk.openwrap.banner.b bVar) {
        this.g = bVar;
    }

    public void setGAMAdSizes(@NonNull h... hVarArr) {
        if (this.f == null || o.isNull(hVarArr)) {
            POBLog.warn("DFPBannerEventHandler", "Can't set the ad sizes, AdManagerAdView or ad sizes are null.", new Object[0]);
        } else {
            this.f.setAdSizes(hVarArr);
        }
    }

    /* renamed from: com.pubmatic.sdk.openwrap.eventhandler.dfp.b$b, reason: collision with other inner class name */
    public class C0018b extends com.google.android.gms.ads.d {
        private C0018b() {
        }

        @Override // com.google.android.gms.ads.d, com.google.android.gms.ads.internal.client.InterfaceC1582a
        public void onAdClicked() {
            if (b.this.g != null) {
                b.this.g.onAdClick();
            }
        }

        @Override // com.google.android.gms.ads.d
        public void onAdClosed() {
            if (b.this.g != null) {
                b.this.g.onAdClosed();
            }
        }

        @Override // com.google.android.gms.ads.d
        public void onAdFailedToLoad(@NonNull com.google.android.gms.ads.l lVar) {
            POBLog.info("DFPBannerEventHandler", "Ad failed to load", new Object[0]);
            int i = lVar.a;
            if (b.this.g != null) {
                b.this.g.onFailed(d.a(lVar));
                return;
            }
            Trace.endSection();
            Trace.endSection();
            POBLog.error("DFPBannerEventHandler", "Can not call failure callback, POBBannerEventListener reference null. GAM error:" + i, new Object[0]);
        }

        @Override // com.google.android.gms.ads.d
        public void onAdImpression() {
            POBLog.info("DFPBannerEventHandler", "GAM banner recorded the impression", new Object[0]);
            if (b.this.c != null) {
                b.this.b();
            } else {
                b.this.j = true;
            }
        }

        @Override // com.google.android.gms.ads.d
        public void onAdLoaded() {
            if (b.this.g == null || b.this.c != null) {
                return;
            }
            if (b.this.d) {
                b.this.e();
            } else {
                b.this.c();
            }
        }

        @Override // com.google.android.gms.ads.d
        public void onAdOpened() {
            if (b.this.g != null) {
                b.this.g.onAdOpened();
            }
        }

        public /* synthetic */ C0018b(b bVar, a aVar) {
            this();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        com.pubmatic.sdk.openwrap.banner.b bVar = this.g;
        if (bVar != null) {
            bVar.onAdImpression();
        }
        this.j = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void c() {
        if (this.c == null) {
            this.c = Boolean.FALSE;
            com.pubmatic.sdk.openwrap.banner.b bVar = this.g;
            if (bVar != null) {
                if (this.f == null) {
                    bVar.onFailed(new com.pubmatic.sdk.common.h(1009, "Ad Server view is not available"));
                    return;
                }
                POBLog.info("DFPBannerEventHandler", "Ad Server Won.", new Object[0]);
                this.g.onAdServerWin(this.f);
                a();
            }
        }
    }

    private void d() {
        l lVar = this.e;
        if (lVar != null) {
            lVar.cancel();
        }
        this.e = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void e() {
        POBLog.debug("DFPBannerEventHandler", "scheduleDelay", new Object[0]);
        d();
        l lVar = new l(new a());
        this.e = lVar;
        lVar.start(400L);
    }

    @NonNull
    private AdManagerAdView a(@NonNull Context context, @NonNull String str) {
        AdManagerAdView adManagerAdView = new AdManagerAdView(context);
        this.f = adManagerAdView;
        adManagerAdView.setAdUnitId(str);
        C0018b c0018b = new C0018b(this, null);
        this.h = c0018b;
        this.f.setAdListener(c0018b);
        this.f.setAppEventListener(this);
        return this.f;
    }

    public b(@NonNull Context context, @NonNull String str, @NonNull h hVar, @NonNull f[] fVarArr) {
        AdManagerAdView adManagerAdViewA = a(context, str);
        this.f = adManagerAdViewA;
        adManagerAdViewA.setAdSize(hVar);
        this.i = fVarArr;
    }

    private void a() {
        if (this.j) {
            b();
        }
    }

    private void a(com.pubmatic.sdk.common.h hVar) {
        com.pubmatic.sdk.openwrap.banner.b bVar = this.g;
        if (bVar == null || hVar == null) {
            return;
        }
        bVar.onFailed(hVar);
    }
}
