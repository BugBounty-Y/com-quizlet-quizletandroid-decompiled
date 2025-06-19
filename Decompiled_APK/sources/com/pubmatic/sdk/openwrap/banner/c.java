package com.pubmatic.sdk.openwrap.banner;

import android.content.Context;
import android.os.Trace;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.base.g;
import com.pubmatic.sdk.common.base.j;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.a;
import com.pubmatic.sdk.common.utility.i;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.openwrap.core.h;
import com.pubmatic.sdk.openwrap.core.k;
import com.pubmatic.sdk.openwrap.core.l;
import com.pubmatic.sdk.openwrap.core.p;
import com.pubmatic.sdk.openwrap.core.t;
import com.pubmatic.sdk.openwrap.core.u;
import com.pubmatic.sdk.openwrap.core.v;
import com.pubmatic.sdk.openwrap.core.y;
import java.util.UUID;

/* loaded from: classes2.dex */
public class c extends FrameLayout implements h {
    private static final com.pubmatic.sdk.common.f a = com.pubmatic.sdk.common.f.BANNER_SIZE_300x250;
    private static boolean b;

    @NonNull
    private static final FrameLayout.LayoutParams c;
    private boolean d;
    private View e;
    private int f;
    private int g;
    private com.pubmatic.sdk.common.base.f h;
    private v i;
    private com.pubmatic.sdk.openwrap.banner.a j;
    private com.pubmatic.sdk.openwrap.core.d k;
    private a l;
    private View m;
    private boolean n;

    @NonNull
    private EnumC0016c o;
    private i p;
    private com.pubmatic.sdk.openwrap.banner.b q;
    private com.pubmatic.sdk.common.base.d r;
    private com.pubmatic.sdk.common.utility.h s;
    private com.pubmatic.sdk.common.ui.a t;
    private boolean u;
    private com.pubmatic.sdk.common.ui.a v;
    private k w;
    private com.pubmatic.sdk.common.models.a x;
    private View y;
    private com.pubmatic.sdk.common.cache.b z;

    public static class a {
        public void onAdClicked(@NonNull c cVar) {
        }

        public void onAdClosed(@NonNull c cVar) {
        }

        public void onAdFailed(@NonNull c cVar, @NonNull com.pubmatic.sdk.common.h hVar) {
        }

        public void onAdImpression(@NonNull c cVar) {
        }

        public void onAdOpened(@NonNull c cVar) {
        }

        public void onAdReceived(@NonNull c cVar) {
        }

        public void onAppLeaving(@NonNull c cVar) {
        }
    }

    public class b implements com.pubmatic.sdk.common.base.d {
        private b() {
        }

        private com.pubmatic.sdk.common.models.a a(@NonNull com.pubmatic.sdk.common.models.a aVar, @NonNull com.pubmatic.sdk.common.base.c cVar) {
            if (!(cVar instanceof com.pubmatic.sdk.openwrap.core.f)) {
                return aVar;
            }
            com.pubmatic.sdk.openwrap.core.f fVar = (com.pubmatic.sdk.openwrap.core.f) cVar;
            if (!fVar.isStaticBid()) {
                return aVar;
            }
            a.C0010a c0010a = new a.C0010a(aVar);
            c0010a.updateWinningBid(fVar);
            return c0010a.build();
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdExpired() {
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdImpression() {
            c.this.n();
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdInteractionStarted() {
            c.this.d();
            c.c(c.this);
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdInteractionStopped() {
            c.this.c();
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdReadyToRefresh(int i) {
            if (c.this.d) {
                return;
            }
            c.this.a(i);
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdRender(@NonNull View view, com.pubmatic.sdk.common.base.c cVar) {
            POBLog.debug("POBBannerView", "onAdRender()", new Object[0]);
            if (c.this.x != null && cVar != null) {
                c cVar2 = c.this;
                cVar2.x = a(cVar2.x, cVar);
            }
            c.this.u = true;
            if (!c.this.d) {
                c.this.e(view);
                return;
            }
            Trace.endSection();
            c.this.e = view;
            POBLog.debug("POBBannerView", "Defer UI attachment for %s ad", "OW");
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
            com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(c.this.x);
            if (winningBid != null && c.this.x != null) {
                POBLog.info("POBBannerView", "On rendering failed for Partner %s, with Error : %s", winningBid.getPartnerName(), hVar.toString());
            }
            c.this.a(hVar);
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onAdUnload() {
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onLeavingApplication() {
            c.this.p();
            c.c(c.this);
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onRenderAdClick() {
            if (c.this.l != null) {
                c.this.l.onAdClicked(c.this);
            }
        }

        @Override // com.pubmatic.sdk.common.base.d
        public void onRenderProcessGone() {
            c.this.r();
            c.this.m = null;
            c cVar = c.this;
            cVar.a(cVar.f);
        }
    }

    /* renamed from: com.pubmatic.sdk.openwrap.banner.c$c, reason: collision with other inner class name */
    public enum EnumC0016c {
        DEFAULT,
        LOADING,
        WAITING,
        WAITING_FOR_REFRESH,
        CREATIVE_LOADING,
        RENDERED,
        WAITING_FOR_AS_RESPONSE
    }

    public class d implements com.pubmatic.sdk.openwrap.banner.b {
        private d() {
        }

        private void a() {
            c.this.n = true;
            POBLog.debug("POBBannerView", "PartnerBidWin", new Object[0]);
            com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(c.this.x);
            if (winningBid != null) {
                winningBid.setHasWon(true);
                o.logBidWinningStatus(winningBid.hasWon(), winningBid.getPartnerName());
                String partnerName = winningBid.getPartnerName();
                if (c.this.j != null && partnerName != null) {
                    c cVar = c.this;
                    cVar.v = cVar.j.getRenderer(partnerName);
                }
                c.this.b(winningBid);
            }
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public j getBidsProvider() {
            return c.this.x;
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public void onAdClick() {
            c.this.m();
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public void onAdClosed() {
            c.this.k();
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b
        public void onAdExecutionComplete() {
            c.this.setState(EnumC0016c.DEFAULT);
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public void onAdImpression() {
            c.this.setAdServerViewVisibility(false);
            if (c.this.n) {
                return;
            }
            c.this.n();
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public void onAdLeftApplication() {
            c.this.p();
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b, com.pubmatic.sdk.openwrap.core.a
        public void onAdOpened() {
            c.this.o();
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b
        public void onAdServerWin(@NonNull View view) {
            c.this.n = false;
            c.this.u = true;
            Trace.endSection();
            if (!c.this.d) {
                c.this.d(view);
                return;
            }
            Trace.endSection();
            c.this.e = view;
            POBLog.debug("POBBannerView", "Defer UI attachment for %s ad", "Ad Server");
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b
        public void onFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
            c.this.a(hVar);
        }

        @Override // com.pubmatic.sdk.openwrap.banner.b
        public void onOpenWrapPartnerWin(String str) {
            if (c.this.x != null) {
                com.pubmatic.sdk.openwrap.core.f fVar = (com.pubmatic.sdk.openwrap.core.f) c.this.x.getBid(str);
                if (fVar != null) {
                    a.C0010a c0010aUpdateWinningBid = new a.C0010a(c.this.x).updateWinningBid(fVar);
                    c.this.x = c0010aUpdateWinningBid.build();
                } else {
                    POBLog.debug("POBBannerView", "bidId is invalid in onOpenWrapPartnerWin(), rendering the client-side winning bid", new Object[0]);
                }
            }
            a();
        }
    }

    public class e implements com.pubmatic.sdk.common.utility.h {
        private e() {
        }

        @Override // com.pubmatic.sdk.common.utility.h
        public void invoke() {
            if (!c.this.u || c.this.b()) {
                o.runOnMainThread(new com.pubmatic.sdk.openwrap.banner.f(this));
                return;
            }
            POBLog.debug("POBBannerView", "Banner is not visibile.", new Object[0]);
            c cVar = c.this;
            cVar.a(cVar.f);
        }
    }

    public class f implements g {
        private f() {
        }

        @Override // com.pubmatic.sdk.common.base.g
        public void onBidsFailed(@NonNull com.pubmatic.sdk.common.base.i iVar, @NonNull com.pubmatic.sdk.common.h hVar) {
            POBLog.debug("POBBannerView", "onBidsFailed : errorMessage= " + hVar, new Object[0]);
            if (c.this.w == null) {
                if (c.this.j instanceof com.pubmatic.sdk.openwrap.banner.e) {
                    c.this.a(hVar);
                    return;
                } else {
                    c.this.a((com.pubmatic.sdk.openwrap.core.f) null);
                    return;
                }
            }
            POBLog.debug("POBBannerView", "Notifying error through bid event delegate - %s", hVar.getErrorMessage());
            c.this.setState(EnumC0016c.WAITING);
            ((com.quizlet.openwrap.b) c.this.w).onBidFailed(c.this, hVar);
        }

        @Override // com.pubmatic.sdk.common.base.g
        public void onBidsFetched(@NonNull com.pubmatic.sdk.common.base.i iVar, @NonNull com.pubmatic.sdk.common.models.a aVar) {
            c.this.x = com.pubmatic.sdk.openwrap.core.b.updateResponseUsingPlacementType(aVar, "inline");
            com.pubmatic.sdk.openwrap.core.f fVar = (com.pubmatic.sdk.openwrap.core.f) c.this.x.getWinningBid();
            if (fVar != null) {
                POBLog.debug("POBBannerView", "onBidsFetched : ImpressionId=%s, BidPrice=%s", fVar.getImpressionId(), String.valueOf(fVar.getPrice()));
            }
            c.this.setRefreshInterval(fVar);
            if (c.this.w == null) {
                c.this.a(fVar);
                return;
            }
            c.this.setState(EnumC0016c.WAITING);
            if (fVar != null && fVar.getStatus() == 1) {
                POBLog.debug("POBBannerView", "Sharing bids through bid event delegate.", new Object[0]);
                ((com.quizlet.openwrap.b) c.this.w).onBidReceived(c.this, fVar);
                return;
            }
            com.pubmatic.sdk.common.h hVar = new com.pubmatic.sdk.common.h(1002, "No ads available");
            POBLog.info("POBBannerView", "Notifying error through bid event delegate - %s", hVar.getErrorMessage());
            ((com.quizlet.openwrap.b) c.this.w).onBidFailed(c.this, hVar);
        }
    }

    static {
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        c = layoutParams;
        layoutParams.gravity = 17;
    }

    public c(@NonNull Context context) {
        this(context, null);
        a(new com.pubmatic.sdk.openwrap.banner.e());
    }

    public static /* synthetic */ com.pubmatic.sdk.openwrap.core.d c(c cVar) {
        cVar.getClass();
        return null;
    }

    private Context getAppContext() {
        return getContext().getApplicationContext();
    }

    @NonNull
    private String getImpressionId() {
        return UUID.randomUUID().toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setAdServerViewVisibility(boolean z) {
        POBLog.info("POBBannerView", "is adserverview available %s", this.y);
        View view = this.y;
        if (view != null) {
            view.setVisibility(z ? 0 : 8);
        }
    }

    private void setRefreshInterval(int i) {
        this.f = o.getValidRefreshInterval(i, 5);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setState(@NonNull EnumC0016c enumC0016c) {
        this.o = enumC0016c;
    }

    public void destroy() {
        POBLog.debug("POBBannerView", "destroy invoked.", new Object[0]);
        f();
        this.p = null;
        this.e = null;
        g();
        com.pubmatic.sdk.openwrap.banner.a aVar = this.j;
        if (aVar != null) {
            aVar.destroy();
        }
        this.l = null;
        this.w = null;
        this.r = null;
        this.s = null;
        this.q = null;
        this.y = null;
    }

    public boolean forceRefresh() {
        if (!a()) {
            return false;
        }
        f();
        loadAd();
        return true;
    }

    public v getAdRequest() {
        v vVar = this.i;
        if (vVar != null) {
            return vVar;
        }
        POBLog.warn("POBBannerView", "Please call POBBannerView.init() before calling getAdRequest()", new Object[0]);
        return null;
    }

    @Override // com.pubmatic.sdk.openwrap.core.h
    public com.pubmatic.sdk.openwrap.core.f getBid() {
        return l.getWinningBid(this.x);
    }

    public com.pubmatic.sdk.common.f getCreativeSize() {
        if (!this.n) {
            com.pubmatic.sdk.openwrap.banner.a aVar = this.j;
            if (aVar != null) {
                return aVar.getAdSize();
            }
            return null;
        }
        com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(this.x);
        if (winningBid != null) {
            return (winningBid.isVideo() && winningBid.getWidth() == 0 && winningBid.getHeight() == 0) ? a : new com.pubmatic.sdk.common.f(winningBid.getWidth(), winningBid.getHeight());
        }
        POBLog.warn("POBBannerView", "getCreativeSize() called for null bid", new Object[0]);
        return null;
    }

    public p getImpression() {
        return com.pubmatic.sdk.openwrap.core.b.getImpression(this.i);
    }

    public void init(@NonNull String str, int i, @NonNull String str2, @NonNull com.pubmatic.sdk.openwrap.banner.a aVar) {
        com.pubmatic.sdk.common.f[] fVarArrRequestedAdSizes = aVar == null ? null : aVar.requestedAdSizes();
        com.pubmatic.sdk.common.h hVarA = a(str, str2, aVar, fVarArrRequestedAdSizes);
        if (hVarA != null) {
            POBLog.error("POBBannerView", hVarA.toString(), new Object[0]);
            return;
        }
        destroy();
        this.s = new e();
        a(aVar);
        i iVar = new i();
        this.p = iVar;
        iVar.setListener(this.s);
        this.p.setNetworkMonitor(com.pubmatic.sdk.common.i.getNetworkMonitor(getAppContext()));
        p pVar = new p(getImpressionId(), str2);
        if (fVarArrRequestedAdSizes != null) {
            pVar.setBanner(new com.pubmatic.sdk.openwrap.core.c(fVarArrRequestedAdSizes));
            if (a(fVarArrRequestedAdSizes)) {
                pVar.setVideo(new y(y.b.IN_BANNER, y.a.LINEAR, a));
            }
        }
        this.z = com.pubmatic.sdk.common.i.getCacheManager(getAppContext());
        v vVarCreateInstance = v.createInstance(str, i, pVar);
        this.i = vVarCreateInstance;
        if (vVarCreateInstance != null) {
            setRefreshInterval(30);
        }
    }

    public void loadAd() {
        p impression = getImpression();
        com.pubmatic.sdk.openwrap.banner.a aVar = this.j;
        com.pubmatic.sdk.common.f[] fVarArrRequestedAdSizes = aVar != null ? aVar.requestedAdSizes() : null;
        if (this.i == null || impression == null || fVarArrRequestedAdSizes == null) {
            POBLog.error("POBBannerView", "Unable to process loadAd() please ensure banner is initialized with valid ad tag details and ad sizes.", new Object[0]);
            return;
        }
        EnumC0016c enumC0016c = this.o;
        if (enumC0016c != EnumC0016c.DEFAULT) {
            POBLog.error("POBBannerView", "Skipping loadAd() as ad is already in %s state", enumC0016c.name());
            return;
        }
        Trace.beginSection("POB Banner Load Ad");
        Trace.beginSection("POB Request Building");
        this.o = EnumC0016c.LOADING;
        j();
    }

    public void pauseAutoRefresh() {
        i iVar = this.p;
        if (iVar == null) {
            POBLog.info("POBBannerView", "Can't pause refresh, banner instance is not valid.", new Object[0]);
        } else if (this.f > 0) {
            iVar.forcePause();
        } else {
            POBLog.info("POBBannerView", "Skipping pause auto-refresh as refresh is disabled.", new Object[0]);
        }
    }

    @Override // com.pubmatic.sdk.openwrap.core.h
    @Deprecated
    public void proceedOnError(@NonNull com.pubmatic.sdk.openwrap.core.g gVar) {
        proceedOnError(gVar, gVar.getErrorMessage());
    }

    @Override // com.pubmatic.sdk.openwrap.core.h
    public boolean proceedToLoadAd() {
        if (this.w == null) {
            POBLog.warn("POBBannerView", "'POBBidEventListener' not implemented", new Object[0]);
            return false;
        }
        if (this.o != EnumC0016c.WAITING) {
            POBLog.warn("POBBannerView", "Can not proceed before calling loadAd() or already in the process of proceed.", new Object[0]);
            return false;
        }
        POBLog.info("POBBannerView", "Bid won client side auction. Hence proceeding to load.", new Object[0]);
        com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(this.x);
        if (winningBid == null || !winningBid.isExpired()) {
            POBLog.debug("POBBannerView", "Proceeding with bid.", new Object[0]);
            setState(EnumC0016c.LOADING);
            a(winningBid);
            return true;
        }
        com.pubmatic.sdk.common.h hVarConvertToPOBError = com.pubmatic.sdk.openwrap.core.j.convertToPOBError(com.pubmatic.sdk.openwrap.core.g.BID_EXPIRED);
        if (this.j instanceof com.pubmatic.sdk.openwrap.banner.e) {
            a(hVarConvertToPOBError);
            return false;
        }
        POBLog.warn("POBBannerView", "Bid expired! Invoking ad server call by ignoring OpenWrap Bid.", new Object[0]);
        h();
        return true;
    }

    public void resumeAutoRefresh() {
        i iVar = this.p;
        if (iVar == null) {
            POBLog.info("POBBannerView", "Can't resume refresh, banner instance is not valid.", new Object[0]);
        } else if (this.f > 0) {
            iVar.forceResume();
        } else {
            POBLog.info("POBBannerView", "Skipping resume auto-refresh as refresh is disabled.", new Object[0]);
        }
    }

    @Override // com.pubmatic.sdk.openwrap.core.h
    public void setBidEventListener(k kVar) {
        this.w = kVar;
    }

    public void setListener(a aVar) {
        this.l = aVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void e() {
        this.x = null;
        this.n = false;
        setAdServerViewVisibility(false);
        if (this.i == null) {
            b(new com.pubmatic.sdk.common.h(1001, "Missing ad request parameters. Please check."));
            POBLog.error("POBBannerView", "Missing ad request parameters. Please check.", new Object[0]);
            return;
        }
        setState(EnumC0016c.LOADING);
        com.pubmatic.sdk.common.cache.b bVar = this.z;
        if (bVar != null) {
            a(this.i, bVar);
        }
        a(this.i).requestBid();
    }

    private void f() {
        setState(EnumC0016c.DEFAULT);
        i iVar = this.p;
        if (iVar != null) {
            iVar.destroy();
        }
        com.pubmatic.sdk.common.base.f fVar = this.h;
        if (fVar != null) {
            fVar.setBidderListener(null);
            this.h.destroy();
            this.h = null;
        }
    }

    private void g() {
        com.pubmatic.sdk.common.ui.a aVar = this.t;
        if (aVar != null) {
            aVar.setAdRendererListener(null);
            this.t.destroy();
            this.t = null;
        }
        com.pubmatic.sdk.common.ui.a aVar2 = this.v;
        if (aVar2 != null) {
            aVar2.setAdRendererListener(null);
            this.v.destroy();
            this.v = null;
        }
    }

    private void h() {
        setState(EnumC0016c.LOADING);
        com.pubmatic.sdk.common.models.a aVar = this.x;
        if (aVar != null) {
            this.x = new a.C0010a(aVar).setWinningBid(null).build();
        }
        com.pubmatic.sdk.openwrap.banner.a aVar2 = this.j;
        if (aVar2 != null) {
            POBLog.info("POBBannerView", "Proceeding with bid. Ad server integration is ".concat(aVar2.getClass().getSimpleName()), new Object[0]);
        }
        a((com.pubmatic.sdk.openwrap.core.f) null);
    }

    private boolean i() {
        return this.f > 0;
    }

    private void j() {
        this.u = false;
        e();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void k() {
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdClosed(this);
        }
    }

    private void l() {
        Trace.endSection();
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdReceived(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void m() {
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdClicked(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void n() {
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdImpression(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void o() {
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdOpened(this);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void p() {
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAppLeaving(this);
        }
    }

    private void q() {
        ViewGroup viewGroup;
        View view = this.y;
        if (view == null || (viewGroup = (ViewGroup) view.getParent()) == null) {
            return;
        }
        viewGroup.removeView(this.y);
        this.y = null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void r() {
        View view = this.m;
        if (view != null) {
            removeView(view);
        }
    }

    private void s() {
        if (i()) {
            setState(EnumC0016c.WAITING_FOR_REFRESH);
        } else {
            setState(EnumC0016c.DEFAULT);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setRefreshInterval(com.pubmatic.sdk.openwrap.core.f fVar) {
        if (fVar != null) {
            setRefreshInterval(fVar.getRefreshInterval());
        } else {
            setRefreshInterval(this.f);
        }
    }

    @Override // com.pubmatic.sdk.openwrap.core.h
    public void proceedOnError(@NonNull com.pubmatic.sdk.openwrap.core.g gVar, @NonNull String str) {
        if (this.w == null) {
            POBLog.warn("POBBannerView", "'POBBidEventListener' not implemented", new Object[0]);
            return;
        }
        if (this.o != EnumC0016c.WAITING) {
            POBLog.warn("POBBannerView", "Can not proceed before calling loadAd() or already in the process of proceed.", new Object[0]);
            return;
        }
        POBLog.info("POBBannerView", "Bid lost client side auction. Hence proceeding with error.", new Object[0]);
        if (!(this.j instanceof com.pubmatic.sdk.openwrap.banner.e)) {
            h();
            return;
        }
        POBLog.info("POBBannerView", "Notified with error code - " + gVar + " description - " + str, new Object[0]);
        a(this.f);
    }

    public c(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d(@NonNull View view) {
        POBLog.debug("POBBannerView", "Show ad for %s", "Ad Server");
        com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(this.x);
        if (winningBid != null) {
            o.logBidWinningStatus(winningBid.hasWon(), winningBid.getPartnerName());
        } else {
            POBLog.debug("POBBannerView", "AdServerWin", new Object[0]);
        }
        c(view);
        a(view);
        a(this.f);
        l();
    }

    public c(@NonNull Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.o = EnumC0016c.DEFAULT;
    }

    private void b(@NonNull com.pubmatic.sdk.common.h hVar) {
        Trace.endSection();
        POBLog.error("POBBannerView", "Failed to receive ad with error - " + hVar, new Object[0]);
        a aVar = this.l;
        if (aVar != null) {
            aVar.onAdFailed(this, hVar);
        }
    }

    private void c(View view) {
        if (view == null) {
            POBLog.verbose("POBBannerView", "Passed rendered view is null in prepareForUIAttachment(), hence ignoring the attachment in UI", new Object[0]);
            return;
        }
        com.pubmatic.sdk.common.ui.a aVar = this.t;
        if (aVar != null) {
            aVar.destroy();
        }
        this.t = this.v;
        this.v = null;
        r();
        q();
        this.m = view;
    }

    public c(@NonNull Context context, @NonNull String str, int i, @NonNull String str2, @NonNull com.pubmatic.sdk.common.f... fVarArr) {
        this(context, str, i, str2, new com.pubmatic.sdk.openwrap.banner.e(fVarArr));
    }

    public c(@NonNull Context context, @NonNull String str, int i, @NonNull String str2, @NonNull com.pubmatic.sdk.openwrap.banner.a aVar) {
        this(context, null, 0);
        init(str, i, str2, aVar);
    }

    private void b(@NonNull View view) {
        int iConvertDpToPixel;
        int iConvertDpToPixel2;
        com.pubmatic.sdk.common.f creativeSize = getCreativeSize();
        POBLog.debug("POBBannerView", "Creative ad size is %s", creativeSize);
        if (creativeSize == null || creativeSize.getAdWidth() <= 0 || creativeSize.getAdHeight() <= 0) {
            iConvertDpToPixel = -1;
            iConvertDpToPixel2 = -1;
        } else {
            iConvertDpToPixel = o.convertDpToPixel(creativeSize.getAdWidth());
            iConvertDpToPixel2 = o.convertDpToPixel(creativeSize.getAdHeight());
        }
        com.pubmatic.sdk.openwrap.banner.a aVar = this.j;
        if (aVar != null) {
            this.y = aVar.getAdServerView();
        }
        if (this.y != null) {
            setAdServerViewVisibility(true);
            addView(this.y, 0, c);
        }
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(iConvertDpToPixel, iConvertDpToPixel2);
        layoutParams.gravity = 17;
        addView(view, layoutParams);
    }

    private void a(@NonNull com.pubmatic.sdk.openwrap.banner.a aVar) {
        this.r = new b();
        d dVar = new d();
        this.q = dVar;
        if (aVar != null) {
            this.j = aVar;
            aVar.setEventListener(dVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d() {
        if (this.g == 0) {
            b = true;
            i iVar = this.p;
            if (iVar != null) {
                iVar.pause();
            }
            this.d = true;
            o();
        }
        this.g++;
    }

    public void loadAd(@NonNull String str) {
        if (!o.isNullOrEmpty(str)) {
            EnumC0016c enumC0016c = this.o;
            if (enumC0016c == EnumC0016c.DEFAULT) {
                Trace.beginSection("POB Banner Load Ad");
                Trace.beginSection("POB Response Parsing");
                this.x = null;
                this.o = EnumC0016c.LOADING;
                a(str).requestBid();
                return;
            }
            POBLog.error("POBBannerView", "Skipping loadAd() as ad is already in %s state", enumC0016c.name());
            return;
        }
        b(new com.pubmatic.sdk.common.h(1007, "Invalid Bid Response."));
        POBLog.error("POBBannerView", "Invalid Bid Response.", new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void e(@NonNull View view) {
        com.pubmatic.sdk.openwrap.core.f winningBid = l.getWinningBid(this.x);
        if (winningBid != null) {
            POBLog.debug("POBBannerView", "Show ad for OW partner : %s", winningBid.getPartnerName());
        }
        c(view);
        b(view);
        setState(EnumC0016c.RENDERED);
        l();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void c() {
        int i = this.g - 1;
        this.g = i;
        if (i == 0) {
            b = false;
            i iVar = this.p;
            if (iVar != null) {
                iVar.resume();
            }
            this.d = false;
            k();
            View view = this.e;
            if (view != null) {
                if (this.n) {
                    e(view);
                    com.pubmatic.sdk.common.models.a aVar = this.x;
                    com.pubmatic.sdk.openwrap.core.f fVar = aVar != null ? (com.pubmatic.sdk.openwrap.core.f) aVar.getWinningBid() : null;
                    if (fVar != null && !fVar.isVideo()) {
                        a(this.f);
                    }
                } else {
                    d(view);
                }
                this.e = null;
            }
        }
    }

    private com.pubmatic.sdk.common.h a(@NonNull String str, @NonNull String str2, com.pubmatic.sdk.openwrap.banner.a aVar, com.pubmatic.sdk.common.f... fVarArr) {
        if (!com.pubmatic.sdk.openwrap.core.b.validate(getContext(), str, str2, aVar) || o.isNull(fVarArr)) {
            return new com.pubmatic.sdk.common.h(1001, "Invalid/Missing ad request parameters like Publisher Id, Profile Id, Banner ad sizes. Please check.");
        }
        return null;
    }

    private boolean a(@NonNull com.pubmatic.sdk.common.f[] fVarArr) {
        for (com.pubmatic.sdk.common.f fVar : fVarArr) {
            if (a.equals(fVar)) {
                return true;
            }
        }
        return false;
    }

    private boolean a() {
        EnumC0016c enumC0016c = this.o;
        if (enumC0016c != EnumC0016c.WAITING_FOR_AS_RESPONSE && enumC0016c != EnumC0016c.CREATIVE_LOADING && !this.d) {
            return true;
        }
        POBLog.debug("POBBannerView", "ForceRefresh is not allowed as banner is in %s state or it is clicked.", enumC0016c);
        return false;
    }

    public void init(@NonNull String str, int i, @NonNull String str2, @NonNull com.pubmatic.sdk.common.f... fVarArr) {
        init(str, i, str2, new com.pubmatic.sdk.openwrap.banner.e(fVarArr));
    }

    private void a(@NonNull v vVar, @NonNull com.pubmatic.sdk.common.cache.b bVar) {
        bVar.requestProfileConfiguration(vVar.getPubId(), vVar.getProfileId(), vVar.getVersionId());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0058  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean b() {
        /*
            r5 = this;
            android.content.Context r0 = r5.getAppContext()
            boolean r0 = com.pubmatic.sdk.common.network.i.isNetworkAvailable(r0)
            r1 = 0
            if (r0 != 0) goto L10
            java.lang.String r0 = "Network not available"
        Ld:
            r2 = r0
            r0 = r1
            goto L40
        L10:
            boolean r0 = r5.isAttachedToWindow()
            if (r0 != 0) goto L19
            java.lang.String r0 = "Banner ad is not attached"
            goto Ld
        L19:
            boolean r0 = r5.hasWindowFocus()
            if (r0 != 0) goto L22
            java.lang.String r0 = "Banner ad is not in active screen"
            goto Ld
        L22:
            boolean r0 = r5.isShown()
            if (r0 != 0) goto L2b
            java.lang.String r0 = "Banner ad is not shown or visible"
            goto Ld
        L2b:
            r0 = 1
            boolean r2 = com.pubmatic.sdk.common.utility.o.isViewVisible(r5, r0)
            if (r2 != 0) goto L38
            java.util.Locale.getDefault()
            java.lang.String r0 = "Banner ad visibility is less than 1 pixel"
            goto Ld
        L38:
            boolean r2 = com.pubmatic.sdk.openwrap.banner.c.b
            if (r2 == 0) goto L3f
            java.lang.String r0 = "Banner view is in background"
            goto Ld
        L3f:
            r2 = 0
        L40:
            java.lang.String r3 = "POBBannerView"
            if (r0 != 0) goto L58
            java.lang.String r1 = ", refreshing banner ad after %s secs."
            java.lang.String r1 = android.support.v4.media.session.a.k(r2, r1)
            int r2 = r5.f
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            java.lang.Object[] r2 = new java.lang.Object[]{r2}
            com.pubmatic.sdk.common.log.POBLog.warn(r3, r1, r2)
            return r0
        L58:
            java.util.Locale.getDefault()
            int r2 = com.pubmatic.sdk.common.utility.o.getViewVisiblePixel(r5)
            java.lang.StringBuilder r4 = new java.lang.StringBuilder
            r4.<init>()
            r4.append(r2)
            java.lang.String r2 = " pixel of Banner ad is visible"
            r4.append(r2)
            java.lang.String r2 = r4.toString()
            java.lang.Object[] r1 = new java.lang.Object[r1]
            com.pubmatic.sdk.common.log.POBLog.warn(r3, r2, r1)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.pubmatic.sdk.openwrap.banner.c.b():boolean");
    }

    @NonNull
    private com.pubmatic.sdk.common.base.f a(@NonNull v vVar) {
        com.pubmatic.sdk.common.models.i profileInfo;
        if (this.h == null) {
            if (this.z != null) {
                profileInfo = this.z.getProfileInfo(o.getMappingKey(vVar.getProfileId(), vVar.getVersionId()));
            } else {
                profileInfo = null;
            }
            l lVar = new l(t.createPOBManager(getAppContext(), vVar, profileInfo));
            this.h = lVar;
            lVar.setBidderListener(new f());
        }
        return this.h;
    }

    @NonNull
    private com.pubmatic.sdk.common.base.f a(@NonNull String str) {
        com.pubmatic.sdk.openwrap.core.o oVar = new com.pubmatic.sdk.openwrap.core.o(str);
        this.h = oVar;
        oVar.setBidderListener(new f());
        return this.h;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull com.pubmatic.sdk.common.h hVar) {
        a(this.f);
        b(hVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(com.pubmatic.sdk.openwrap.core.f fVar) {
        this.o = EnumC0016c.WAITING_FOR_AS_RESPONSE;
        if (this.j != null) {
            Trace.endSection();
            this.j.requestAd(fVar);
            this.j.getAdInteractionListener();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b(@NonNull com.pubmatic.sdk.openwrap.core.f fVar) {
        if (this.v == null) {
            this.v = u.getBannerRenderer(getAppContext(), fVar.getRemainingExpirationTime());
        }
        this.v.setAdRendererListener(this.r);
        this.o = EnumC0016c.CREATIVE_LOADING;
        this.v.renderAd(fVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(int i) {
        s();
        if (this.p == null || !i()) {
            return;
        }
        this.p.loop(i);
        POBLog.debug("POBBannerView", "loopNextAd with interval %d", Integer.valueOf(i));
    }

    private void a(@NonNull View view) {
        FrameLayout.LayoutParams layoutParams;
        ViewGroup.LayoutParams layoutParams2 = view.getLayoutParams();
        if (layoutParams2 != null) {
            if (layoutParams2 instanceof FrameLayout.LayoutParams) {
                layoutParams = (FrameLayout.LayoutParams) layoutParams2;
                layoutParams.gravity = 17;
            } else {
                a(new com.pubmatic.sdk.common.h(1009, "Ad Server layout params must be of type FrameLayout."));
                return;
            }
        } else {
            layoutParams = c;
        }
        view.setVisibility(0);
        addView(view, layoutParams);
    }
}
