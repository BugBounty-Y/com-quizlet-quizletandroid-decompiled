package org.prebid.mobile;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.text.TextUtils;
import android.view.View;
import androidx.camera.camera2.internal.s0;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import java.lang.ref.WeakReference;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.regex.Pattern;
import org.prebid.mobile.VisibilityMonitor;
import org.prebid.mobile.api.data.AdFormat;
import org.prebid.mobile.api.data.FetchDemandResult;
import org.prebid.mobile.api.exceptions.AdException;
import org.prebid.mobile.configuration.AdUnitConfiguration;
import org.prebid.mobile.configuration.NativeAdUnitConfiguration;
import org.prebid.mobile.rendering.bidding.data.bid.Bid;
import org.prebid.mobile.rendering.bidding.data.bid.BidResponse;
import org.prebid.mobile.rendering.bidding.listeners.BidRequesterListener;
import org.prebid.mobile.rendering.bidding.loader.BidLoader;
import org.prebid.mobile.rendering.sdk.PrebidContextHolder;

/* loaded from: classes3.dex */
public abstract class AdUnit {
    public final AdUnitConfiguration a;
    public BidLoader b;
    public AdManagerAdRequest c;
    public BidResponse d;
    public final VisibilityMonitor e;
    public final WeakReference f;

    public AdUnit(String str, EnumSet enumSet) {
        AdUnitConfiguration adUnitConfiguration = new AdUnitConfiguration();
        this.a = adUnitConfiguration;
        this.e = new VisibilityMonitor();
        this.f = new WeakReference(null);
        adUnitConfiguration.h = str;
        adUnitConfiguration.b = true;
        if (enumSet == null) {
            return;
        }
        if (enumSet.contains(AdFormat.c)) {
            adUnitConfiguration.l = new NativeAdUnitConfiguration();
        }
        EnumSet enumSet2 = adUnitConfiguration.m;
        enumSet2.clear();
        enumSet2.addAll(enumSet);
    }

    public final void a(AdManagerAdRequest adManagerAdRequest, final com.google.firebase.tracing.a aVar) {
        NetworkInfo activeNetworkInfo;
        if (TextUtils.isEmpty(PrebidMobile.b)) {
            LogUtil.a("Empty account id.");
            aVar.b();
            return;
        }
        AdUnitConfiguration adUnitConfiguration = this.a;
        if (TextUtils.isEmpty(adUnitConfiguration.h)) {
            LogUtil.a("Empty config id.");
            aVar.b();
            return;
        }
        if (PrebidMobile.c.equals(Host.b) && TextUtils.isEmpty(PrebidMobile.c.a)) {
            LogUtil.a("Empty host url for custom Prebid Server host.");
            aVar.b();
            return;
        }
        Iterator it2 = adUnitConfiguration.n.iterator();
        while (it2.hasNext()) {
            AdSize adSize = (AdSize) it2.next();
            if (adSize.a < 0 || adSize.b < 0) {
                aVar.b();
                return;
            }
        }
        Context contextA = PrebidContextHolder.a();
        if (contextA == null) {
            LogUtil.a("Invalid context");
            aVar.b();
            return;
        }
        ConnectivityManager connectivityManager = (ConnectivityManager) contextA.getSystemService("connectivity");
        if (connectivityManager != null && contextA.checkCallingOrSelfPermission("android.permission.ACCESS_NETWORK_STATE") == 0 && ((activeNetworkInfo = connectivityManager.getActiveNetworkInfo()) == null || !activeNetworkInfo.isConnected())) {
            aVar.b();
            return;
        }
        HashSet hashSet = Util.a;
        if (adManagerAdRequest == null || (AdManagerAdRequest.class != Util.c("com.google.android.gms.ads.doubleclick.PublisherAdRequest") && AdManagerAdRequest.class != Util.c("com.google.android.gms.ads.admanager.AdManagerAdRequest") && AdManagerAdRequest.class != Util.c("com.google.android.gms.ads.doubleclick.PublisherAdRequest$Builder") && AdManagerAdRequest.class != Util.c("com.google.android.gms.ads.admanager.AdManagerAdRequest$Builder") && AdManagerAdRequest.class != Util.c("android.os.Bundle") && AdManagerAdRequest.class != Util.c("com.applovin.mediation.nativeAds.MaxNativeAdLoader"))) {
            this.c = null;
            aVar.b();
            return;
        }
        this.c = adManagerAdRequest;
        BidLoader bidLoader = new BidLoader(adUnitConfiguration, new BidRequesterListener() { // from class: org.prebid.mobile.AdUnit.1
            @Override // org.prebid.mobile.rendering.bidding.listeners.BidRequesterListener
            public final void a(AdException adException) {
                AdUnit adUnit = AdUnit.this;
                adUnit.d = null;
                Util.a(null, adUnit.c);
                String str = adException.a;
                FetchDemandResult fetchDemandResult = (str.contains("No bids") || str.equals("Failed to parse bids. No winning bids were found.")) ? FetchDemandResult.f : str.contains("Timeout") ? FetchDemandResult.e : (str.contains("Network Error") || str.contains("No internet")) ? FetchDemandResult.d : (Pattern.compile("^Invalid request: Stored Request with ID=\".*\" not found.").matcher(str).find() || str.contains("No stored request")) ? FetchDemandResult.a : (Pattern.compile("^Invalid request: Stored Imp with ID=\".*\" not found.").matcher(str).find() || str.contains("Stored Imp with ID")) ? FetchDemandResult.b : (Pattern.compile("^Invalid request: Request imp\\[\\d\\].banner.format\\[\\d\\] must define non-zero \"h\" and \"w\" properties.").matcher(str).find() || Pattern.compile("Invalid request: Unable to set interstitial size list").matcher(str).find() || str.contains("Request imp[0].banner.format")) ? FetchDemandResult.c : FetchDemandResult.g;
                LogUtil.b("Prebid", "Can't download bids: " + fetchDemandResult);
                fetchDemandResult.ordinal();
                aVar.b();
            }

            @Override // org.prebid.mobile.rendering.bidding.listeners.BidRequesterListener
            public final void b(BidResponse bidResponse) {
                AdUnit adUnit = AdUnit.this;
                adUnit.d = bidResponse;
                Util.a(bidResponse.a(), adUnit.c);
                aVar.b();
                BidResponse bidResponse2 = adUnit.d;
                if (bidResponse2 == null || bidResponse2.b() == null || bidResponse2.b().e == null) {
                    return;
                }
                Bid bidB = bidResponse2.b();
                boolean zFind = false;
                if (bidB != null) {
                    String str = bidB.b;
                    if (!TextUtils.isEmpty(str)) {
                        zFind = Pattern.compile("<VAST\\s.*version\\s*=\\s*\".*\"(\\s.*|)?>").matcher(str).find();
                    }
                }
                if (zFind) {
                    LogUtil.e(3, "AdUnit", "VisibilityTracker ignored due to the video ad");
                    return;
                }
                String str2 = bidResponse2.b().e;
                String str3 = (String) bidResponse2.a().get("hb_cache_id");
                if (str3 == null) {
                    LogUtil.e(5, "AdUnit", "Can't register visibility tracker. There is no hb_cache_id keyword.");
                    return;
                }
                WeakReference weakReference = adUnit.f;
                View view = weakReference != null ? (View) weakReference.get() : null;
                if (view == null) {
                    return;
                }
                VisibilityMonitor visibilityMonitor = adUnit.e;
                VisibilityMonitor.VisibilityTimer visibilityTimer = visibilityMonitor.b;
                visibilityTimer.a();
                boolean z = visibilityMonitor.a;
                visibilityTimer.c = str2;
                visibilityTimer.d = str3;
                visibilityTimer.e = new WeakReference(view);
                visibilityTimer.b = z;
                LogUtil.e(3, "VisibilityTimer", "Start of monitoring...");
                visibilityTimer.start();
            }
        });
        this.b = bidLoader;
        if (adUnitConfiguration.c > 0) {
            bidLoader.e = new s0(13);
            LogUtil.e(2, "PrebidMobile", "Start fetching bids with auto refresh millis: " + adUnitConfiguration.c);
        } else {
            bidLoader.e = null;
            LogUtil.e(2, "PrebidMobile", "Start a single fetching.");
        }
        this.b.b();
    }
}
