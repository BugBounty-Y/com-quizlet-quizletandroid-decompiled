package com.pubmatic.sdk.openwrap.core.interstitial;

import android.app.Activity;
import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.cache.a;
import com.pubmatic.sdk.common.i;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.ui.f;
import com.pubmatic.sdk.common.ui.g;
import com.pubmatic.sdk.common.ui.h;
import com.pubmatic.sdk.video.player.n;
import com.pubmatic.sdk.webrendering.mraid.e;
import com.pubmatic.sdk.webrendering.ui.POBFullScreenActivity;
import com.pubmatic.sdk.webrendering.ui.b;
import com.pubmatic.sdk.webrendering.ui.m;
import com.pubmatic.sdk.webrendering.ui.o;

/* loaded from: classes2.dex */
public class b implements g, com.pubmatic.sdk.video.renderer.d, com.pubmatic.sdk.common.base.d {
    private com.pubmatic.sdk.common.ui.a a;
    private f b;
    private h c;
    private int d;
    private com.pubmatic.sdk.common.base.c e;

    @NonNull
    private final Context f;
    private View g;

    @NonNull
    private final com.pubmatic.sdk.openwrap.core.interstitial.a h;
    private com.pubmatic.sdk.common.ui.d i;
    private com.pubmatic.sdk.webrendering.ui.b j;
    private m k;
    private e l;

    public class a implements o {
        public a() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.o
        public void onSkipOptionUpdate(boolean z) {
            if (b.this.j == null || !b.this.j.isBackButtonEnabled()) {
                return;
            }
            b.this.a(z);
        }
    }

    /* renamed from: com.pubmatic.sdk.openwrap.core.interstitial.b$b, reason: collision with other inner class name */
    public class C0017b implements com.pubmatic.sdk.common.ui.d {
        final /* synthetic */ View a;

        public C0017b(View view) {
            this.a = view;
        }

        @Override // com.pubmatic.sdk.common.ui.d
        public void onCreate(@NonNull Activity activity) {
            View view = this.a;
            if (view instanceof com.pubmatic.sdk.common.view.c) {
                ((com.pubmatic.sdk.common.view.c) view).setBaseContext(activity);
            } else if (view instanceof n) {
                ((n) view).setBaseContext(activity);
            }
        }

        @Override // com.pubmatic.sdk.common.ui.d
        public void onDestroy() {
            View view = this.a;
            if (view instanceof com.pubmatic.sdk.common.view.c) {
                ((com.pubmatic.sdk.common.view.c) view).setBaseContext(b.this.f.getApplicationContext());
            } else if (view instanceof n) {
                ((n) view).setBaseContext(b.this.f.getApplicationContext());
            }
            b.this.onAdInteractionStopped();
        }
    }

    public class c implements com.pubmatic.sdk.webrendering.ui.n {
        public c() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.n
        public void onClose() {
            b.this.a();
        }

        @Override // com.pubmatic.sdk.webrendering.ui.n
        public void onForward() {
            b.this.d();
        }
    }

    public class d implements View.OnClickListener {
        public d() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(@NonNull View view) {
            if (b.this.e != null) {
                com.pubmatic.sdk.common.utility.e.triggerDeepLink(b.this.f, "https://play.google.com/store/apps/details?id=" + b.this.e.getBundle(), true);
                b.this.onRenderAdClick();
            }
        }
    }

    public b(@NonNull Context context, @NonNull com.pubmatic.sdk.openwrap.core.interstitial.a aVar) {
        this.f = context;
        this.h = aVar;
    }

    @Override // com.pubmatic.sdk.common.ui.g
    public void destroy() {
        com.pubmatic.sdk.common.ui.a aVar = this.a;
        if (aVar != null) {
            aVar.destroy();
        }
        b();
    }

    @Override // com.pubmatic.sdk.video.renderer.d
    public void notifyAdEvent(@NonNull com.pubmatic.sdk.common.g gVar) {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdExpired() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdImpression() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStarted() {
        this.d++;
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStopped() {
        this.d--;
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdReadyToRefresh(int i) {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRender(@NonNull View view, com.pubmatic.sdk.common.base.c cVar) {
        this.g = view;
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdUnload() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onLeavingApplication() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderAdClick() {
        m mVar = this.k;
        if (mVar != null) {
            mVar.onAdViewClicked();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderProcessGone() {
        b();
    }

    @Override // com.pubmatic.sdk.video.renderer.d
    public void onSkipOptionUpdate(boolean z) {
        a(z);
    }

    @Override // com.pubmatic.sdk.common.ui.g
    public void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar) {
        this.e = cVar;
        POBLog.debug("POBInterstitialRenderer", "Rendering onStart", new Object[0]);
        if (cVar.getRenderableContent() != null) {
            com.pubmatic.sdk.common.ui.a aVarBuild = this.h.build(cVar, hashCode());
            this.a = aVarBuild;
            if (aVarBuild != null) {
                aVarBuild.setAdRendererListener(this);
                this.a.renderAd(cVar);
            }
        }
    }

    @Override // com.pubmatic.sdk.common.ui.g
    public void setAdRendererListener(f fVar) {
    }

    @Override // com.pubmatic.sdk.common.ui.g
    public void setVideoAdEventListener(h hVar) {
    }

    @Override // com.pubmatic.sdk.common.ui.g
    public void show(int i) {
        a(i);
    }

    private void b() {
        i.getAdViewCacheService().popStoredAdView(Integer.valueOf(hashCode()));
        this.i = null;
        a();
    }

    private void c() {
        com.pubmatic.sdk.common.ui.a aVar = this.a;
        if (aVar != null) {
            aVar.invalidateExpiration();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d() {
        com.pubmatic.sdk.webrendering.ui.f fVar = new com.pubmatic.sdk.webrendering.ui.f(this.f);
        fVar.setInstallButtonClickListener(new d());
        m mVar = this.k;
        if (mVar != null) {
            mVar.addView(fVar);
            e eVar = this.l;
            if (eVar != null) {
                eVar.addFriendlyObstructions(fVar, com.pubmatic.sdk.common.viewability.h.OTHER);
            }
        }
    }

    private void a(int i) {
        View view;
        POBLog.info("POBInterstitialRenderer", "showInterstitialAd", new Object[0]);
        com.pubmatic.sdk.common.base.c cVar = this.e;
        if (cVar != null && (view = this.g) != null) {
            a(cVar, view);
            a.C0008a storedAdView = i.getAdViewCacheService().getStoredAdView(Integer.valueOf(hashCode()));
            if (storedAdView != null) {
                com.pubmatic.sdk.common.ui.a aVar = this.a;
                if (aVar instanceof e) {
                    this.l = (e) aVar;
                    m mVar = (m) storedAdView.getAdView();
                    this.k = mVar;
                    mVar.setEnableSkipTimer(true);
                    this.k.setObstructionUpdateListener(this.l);
                    com.pubmatic.sdk.webrendering.ui.b bVarCreateBannerConfig = b.a.createBannerConfig(this.e.getRawBid(), DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
                    this.j = bVarCreateBannerConfig;
                    int skipAfter = bVarCreateBannerConfig.getSkipAfter();
                    if (skipAfter > 0) {
                        this.k.configureSkippability(skipAfter);
                    }
                    this.k.setSkipOptionUpdateListener(new a());
                    this.l.signalImpressionEvent();
                }
                POBFullScreenActivity.startFullScreenActivity(this.f, i, this.e, hashCode());
                onAdInteractionStarted();
                return;
            }
            return;
        }
        POBLog.error("POBInterstitialRenderer", "Can not show interstitial for descriptor: " + this.e, new Object[0]);
    }

    private void a(@NonNull com.pubmatic.sdk.common.base.c cVar, @NonNull View view) {
        ViewGroup viewGroup;
        this.i = new C0017b(view);
        if (cVar.isVideo()) {
            viewGroup = (ViewGroup) view;
        } else {
            m mVar = new m(this.f.getApplicationContext(), (ViewGroup) view, !com.pubmatic.sdk.common.utility.o.isNullOrEmpty(cVar.getBundle()));
            mVar.setMraidViewContainerListener(new c());
            viewGroup = mVar;
        }
        i.getAdViewCacheService().storeAdView(Integer.valueOf(hashCode()), new a.C0008a(viewGroup, this.i));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(boolean z) {
        POBFullScreenActivity.updateBackButtonState(this.f, hashCode(), z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        POBFullScreenActivity.closeActivity(this.f, hashCode());
    }
}
