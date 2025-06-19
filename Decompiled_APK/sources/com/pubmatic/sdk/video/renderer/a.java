package com.pubmatic.sdk.video.renderer;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.pubmatic.sdk.common.g;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.k;
import com.pubmatic.sdk.common.utility.l;
import com.pubmatic.sdk.common.utility.m;
import com.pubmatic.sdk.video.player.n;
import com.pubmatic.sdk.video.player.o;
import com.pubmatic.sdk.video.vastmodels.j;
import com.pubmatic.sdk.video.vastmodels.l;
import com.pubmatic.sdk.webrendering.ui.p;
import com.pubmatic.sdk.webrendering.ui.q;
import java.util.List;

/* loaded from: classes2.dex */
public class a implements com.pubmatic.sdk.video.renderer.c, o, p, com.pubmatic.sdk.webrendering.ui.o {
    public static final float VIEWABILITY_THRESHOLD_PERCENT_FOR_BANNER = 50.0f;

    @NonNull
    private final String a;
    private com.pubmatic.sdk.common.base.d b;
    private com.pubmatic.sdk.video.renderer.d c;
    private com.pubmatic.sdk.video.renderer.e d;
    private long e;
    private l f;

    @NonNull
    private final n g;
    private com.pubmatic.sdk.common.viewability.n h;

    @NonNull
    private final q i;
    private com.pubmatic.sdk.common.base.c j;
    private com.pubmatic.sdk.common.utility.n k;
    private com.pubmatic.sdk.common.utility.n l;
    private boolean m;

    /* renamed from: com.pubmatic.sdk.video.renderer.a$a, reason: collision with other inner class name */
    public class C0020a implements k {
        public C0020a() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            a.this.a();
        }
    }

    public class b implements m {
        public b() {
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onErrorOpenUrl(@NonNull String str) {
            POBLog.warn("POBVideoRenderer", AbstractC0147y.d("Unable to open icon click url :", str), new Object[0]);
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserClose(@NonNull String str) {
            if (a.this.m) {
                return;
            }
            a.this.c();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserOpen(@NonNull String str) {
            if (a.this.m) {
                return;
            }
            a.this.b();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onLeaveApp(@NonNull String str) {
            if (a.this.m) {
                return;
            }
            a.this.d();
        }
    }

    public class c implements Runnable {
        final /* synthetic */ float a;
        final /* synthetic */ float b;

        public c(float f, float f2) {
            this.a = f;
            this.b = f2;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (a.this.h != null) {
                a.this.h.setTrackView(a.this.g);
                a.this.h.impressionOccurred();
                a.this.h.start(this.a, this.b);
                a.this.h.signalPlayerStateChange("inline".equals(a.this.a) ? com.pubmatic.sdk.common.viewability.m.NORMAL : com.pubmatic.sdk.common.viewability.m.FULLSCREEN);
            }
        }
    }

    public class d implements m {
        public d() {
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onErrorOpenUrl(@NonNull String str) {
            POBLog.warn("POBVideoRenderer", AbstractC0147y.d("Unable to open ", str), new Object[0]);
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserClose(@NonNull String str) {
            a.this.c();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserOpen(@NonNull String str) {
            a.this.b();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onLeaveApp(@NonNull String str) {
            a.this.d();
        }
    }

    public class e implements com.pubmatic.sdk.common.viewability.k {
        final /* synthetic */ float a;

        public e(float f) {
            this.a = f;
        }

        @Override // com.pubmatic.sdk.common.viewability.k
        public void onOmidSessionInitialized() {
            if (a.this.h != null) {
                a.this.h.loaded(a.this.g.getVastPlayerConfig().getSkip() == 1 && a.this.g.getSkipabilityEnabled(), this.a);
            }
        }
    }

    public a(@NonNull n nVar, @NonNull q qVar, @NonNull String str) {
        this.g = nVar;
        this.a = str;
        nVar.setVastPlayerListener(this);
        nVar.setOnSkipOptionUpdateListener(this);
        this.i = qVar;
        qVar.setOnExposureChangeWithThresholdListener(this);
    }

    private int a(int i, int i2) {
        int i3 = i2 - i;
        if (i3 <= 0) {
            return 0;
        }
        return i3;
    }

    private void i() {
        if (this.e > 0) {
            l lVar = new l(new C0020a());
            this.f = lVar;
            lVar.start(this.e);
        }
    }

    private void j() {
        l lVar = this.f;
        if (lVar != null) {
            lVar.cancel();
            this.f = null;
        }
    }

    @Override // com.pubmatic.sdk.video.renderer.c, com.pubmatic.sdk.common.ui.a
    public void destroy() {
        j();
        this.g.destroy();
        this.i.setOnExposureChangeWithThresholdListener(null);
        this.i.destroy();
        com.pubmatic.sdk.common.viewability.n nVar = this.h;
        if (nVar != null) {
            nVar.finishAdSession();
            this.h = null;
        }
        this.l = null;
    }

    public void disableIconClickCallbacks() {
        this.m = true;
    }

    @Override // com.pubmatic.sdk.video.renderer.c, com.pubmatic.sdk.common.ui.a
    public void invalidateExpiration() {
        j();
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onClose() {
        com.pubmatic.sdk.common.base.d dVar;
        if (this.c == null || (dVar = this.b) == null) {
            return;
        }
        dVar.onAdInteractionStopped();
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onEndCardWillLeaveApp() {
        d();
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onFailedToPlay(@NonNull h hVar) {
        j();
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRenderingFailed(hVar);
        }
        if (this.h == null || hVar.getErrorMessage() == null) {
            return;
        }
        this.h.signalError(com.pubmatic.sdk.common.viewability.l.VIDEO, hVar.getErrorMessage());
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onIndustryIconClick(String str) {
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            POBLog.warn("POBVideoRenderer", "Icon clickThrough url is missing.", new Object[0]);
        } else {
            if (this.l == null) {
                this.l = new com.pubmatic.sdk.common.utility.n(this.g.getContext().getApplicationContext(), new b());
            }
            this.l.open(str);
            if (!this.m) {
                e();
            }
        }
        com.pubmatic.sdk.common.viewability.n nVar = this.h;
        if (nVar != null) {
            nVar.signalAdEvent(g.ICON_CLICKED);
        }
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onOpenLandingPage(String str) {
        a(str);
        h();
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onPlaybackCompleted(float f) {
        com.pubmatic.sdk.common.base.c cVar;
        if (this.b != null && (cVar = this.j) != null) {
            this.b.onAdReadyToRefresh(a((int) f, cVar.getRefreshInterval()));
        }
        com.pubmatic.sdk.video.renderer.d dVar = this.c;
        if (dVar != null) {
            dVar.notifyAdEvent(g.COMPLETE);
        }
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onReadyToPlay(j jVar, float f) {
        Context context = this.g.getContext();
        if (context != null) {
            a(context);
        }
        a(jVar, f);
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRender(this.g, null);
        }
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onSkip() {
    }

    @Override // com.pubmatic.sdk.webrendering.ui.o
    public void onSkipOptionUpdate(boolean z) {
        if (this.c == null || !this.g.getVastPlayerConfig().isBackButtonEnabled()) {
            return;
        }
        this.c.onSkipOptionUpdate(z);
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onVideoEventOccurred(@NonNull l.b bVar) {
        if (this.h != null) {
            switch (com.pubmatic.sdk.video.renderer.b.a[bVar.ordinal()]) {
                case 1:
                    this.h.signalAdEvent(g.FIRST_QUARTILE);
                    break;
                case 2:
                    this.h.signalAdEvent(g.MID_POINT);
                    break;
                case 3:
                    this.h.signalAdEvent(g.THIRD_QUARTILE);
                    break;
                case 4:
                    this.h.signalAdEvent(g.COMPLETE);
                    break;
                case 5:
                    this.h.signalAdEvent(g.UNMUTE);
                    break;
                case 6:
                    this.h.signalAdEvent(g.MUTE);
                    break;
                case 7:
                    this.h.signalAdEvent(g.SKIPPED);
                    break;
                case 8:
                    this.h.signalAdEvent(g.RESUME);
                    break;
                case 9:
                    this.h.signalAdEvent(g.PAUSE);
                    break;
            }
        }
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void onVideoStarted(float f, float f2) {
        if (this.h != null) {
            this.g.postDelayed(new c(f, f2), 1000L);
        }
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdImpression();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.ui.p
    public void onViewabilityChanged(boolean z) {
        if (z) {
            g();
        } else {
            f();
        }
    }

    @Override // com.pubmatic.sdk.video.renderer.c
    public void proceedAdSkip(boolean z) {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            if (z) {
                dVar.onAdInteractionStopped();
            } else {
                this.g.play();
            }
        }
    }

    @Override // com.pubmatic.sdk.video.renderer.c, com.pubmatic.sdk.common.ui.a
    public void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar) {
        i();
        this.j = cVar;
        String renderableContent = cVar.getRenderableContent();
        if (renderableContent != null) {
            this.g.load(renderableContent);
            return;
        }
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRenderingFailed(new h(1009, "Rendering failed for descriptor: " + cVar));
        }
    }

    @Override // com.pubmatic.sdk.video.renderer.c, com.pubmatic.sdk.common.ui.a
    public void setAdRendererListener(com.pubmatic.sdk.common.base.d dVar) {
        this.b = dVar;
        if (dVar instanceof com.pubmatic.sdk.video.renderer.d) {
            setVideoRenderingListener((com.pubmatic.sdk.video.renderer.d) dVar);
        }
    }

    public void setExpirationTimeout(long j) {
        this.e = j;
    }

    public void setMeasurementProvider(com.pubmatic.sdk.common.viewability.n nVar) {
        this.h = nVar;
    }

    @Override // com.pubmatic.sdk.video.renderer.c
    public void setVideoRenderingListener(com.pubmatic.sdk.video.renderer.d dVar) {
        this.c = dVar;
    }

    @Override // com.pubmatic.sdk.video.renderer.c
    public void setVideoSkipEventListener(com.pubmatic.sdk.video.renderer.e eVar) {
    }

    @Override // com.pubmatic.sdk.video.player.o
    public void shouldForwardClickEvent() {
        h();
        e();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdInteractionStarted();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void c() {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdInteractionStopped();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d() {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onLeavingApplication();
        }
    }

    private void e() {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onRenderAdClick();
        }
    }

    private void f() {
        this.g.setAutoPlayOnForeground(false);
        this.g.pause();
    }

    private void g() {
        this.g.setAutoPlayOnForeground(true);
        this.g.play();
    }

    private void h() {
        com.pubmatic.sdk.common.viewability.n nVar = this.h;
        if (nVar != null) {
            nVar.signalAdEvent(g.CLICKED);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        com.pubmatic.sdk.common.base.d dVar = this.b;
        if (dVar != null) {
            dVar.onAdExpired();
        }
    }

    private void a(String str) {
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            POBLog.warn("POBVideoRenderer", "Video clickThrough url is missing.", new Object[0]);
        } else {
            POBLog.debug("POBVideoRenderer", "Opening landing page with url: %s", str);
            com.pubmatic.sdk.common.utility.n nVar = this.k;
            if (nVar != null) {
                nVar.open(str);
            }
        }
        e();
    }

    private void a(@NonNull Context context) {
        this.k = new com.pubmatic.sdk.common.utility.n(context, new d());
    }

    private void a(j jVar, float f) {
        if (this.h == null || jVar == null) {
            return;
        }
        a(jVar.getCombinedVerificationList(), f);
    }

    private void a(@NonNull List<com.pubmatic.sdk.common.viewability.j> list, float f) {
        com.pubmatic.sdk.common.viewability.n nVar = this.h;
        if (nVar != null) {
            nVar.startAdSession(this.g, list, new e(f));
            POBLog.debug("POBVideoRenderer", "Video viewability measurement provider initialised", new Object[0]);
        } else {
            POBLog.debug("POBVideoRenderer", "Video viewability measurement provider not initialised", new Object[0]);
        }
    }
}
