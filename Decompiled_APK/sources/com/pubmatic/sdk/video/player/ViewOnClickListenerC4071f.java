package com.pubmatic.sdk.video.player;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.Color;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.log.POBLog;

/* renamed from: com.pubmatic.sdk.video.player.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class ViewOnClickListenerC4071f extends FrameLayout implements InterfaceC4066a, com.pubmatic.sdk.common.base.d, View.OnClickListener {
    private w a;
    private String b;
    private com.pubmatic.sdk.webrendering.mraid.e c;
    private int d;

    @NonNull
    private final ImageView e;
    private com.pubmatic.sdk.webrendering.ui.o f;
    private com.pubmatic.sdk.webrendering.ui.e g;
    private View h;

    /* renamed from: com.pubmatic.sdk.video.player.f$a */
    public class a implements com.pubmatic.sdk.webrendering.ui.d {
        public a() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.d
        public void onTimerExhausted() {
            ViewOnClickListenerC4071f.this.c();
        }
    }

    public ViewOnClickListenerC4071f(@NonNull Context context, boolean z) {
        super(context);
        setBackgroundColor(getResources().getColor(R.color.black));
        if (z) {
            this.e = com.pubmatic.sdk.webrendering.a.createSkipButton(context, com.pubmatic.sdk.video.h.pob_forward_btn, com.pubmatic.sdk.video.g.pob_ic_forward_24);
        } else {
            this.e = com.pubmatic.sdk.webrendering.a.createSkipButton(context, com.pubmatic.sdk.video.h.pob_close_btn, com.pubmatic.sdk.video.g.pob_ic_close_black_24dp);
        }
        this.e.setOnClickListener(this);
    }

    private void b() {
        a();
        d();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void c() {
        com.pubmatic.sdk.webrendering.ui.e eVar = this.g;
        if (eVar == null || eVar.getParent() != this) {
            return;
        }
        removeView(this.g);
        this.e.setVisibility(0);
        a(true);
        this.g = null;
    }

    private void d() {
        setBackgroundColor(Color.argb(204, 0, 0, 0));
    }

    private void e() {
        POBLog.debug("POBMraidEndCardView", "EndCard skipOffset: " + this.d, new Object[0]);
        if (this.d > 0) {
            this.e.setVisibility(4);
            this.g = new com.pubmatic.sdk.webrendering.ui.e(getContext(), this.d);
            a(false);
            this.g.setTimerExhaustedListener(new a());
            addView(this.g);
        } else {
            a(true);
        }
        addView(this.e);
    }

    public void destroy() {
        invalidateRenderer();
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public FrameLayout getView() {
        return this;
    }

    public void invalidateRenderer() {
        com.pubmatic.sdk.webrendering.mraid.e eVar = this.c;
        if (eVar != null) {
            eVar.destroy();
            this.c = null;
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdExpired() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdImpression() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStarted() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStopped() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdReadyToRefresh(int i) {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRender(@NonNull View view, com.pubmatic.sdk.common.base.c cVar) {
        this.h = view;
        if (view.getParent() != null || cVar == null) {
            return;
        }
        w wVar = this.a;
        if (wVar != null) {
            wVar.a();
        }
        C4067b.updateEndCardView(view, this, cVar);
        addView(view, 0);
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
        a(new com.pubmatic.sdk.video.a(602, "End-card failed to render."));
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdUnload() {
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        if (view.getId() == com.pubmatic.sdk.video.h.pob_close_btn) {
            w wVar = this.a;
            if (wVar != null) {
                wVar.onClose();
                return;
            }
            return;
        }
        if (view.getId() == com.pubmatic.sdk.video.h.pob_forward_btn) {
            w wVar2 = this.a;
            if (wVar2 != null) {
                wVar2.d();
                return;
            }
            return;
        }
        if (view.getId() == com.pubmatic.sdk.video.h.pob_learn_more_btn) {
            c();
            w wVar3 = this.a;
            if (wVar3 != null) {
                wVar3.b();
                return;
            }
            return;
        }
        if (view instanceof ViewOnClickListenerC4071f) {
            c();
            w wVar4 = this.a;
            if (wVar4 != null) {
                wVar4.c();
            }
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onLeavingApplication() {
        c();
        w wVar = this.a;
        if (wVar != null) {
            wVar.onEndCardWillLeaveApp();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderAdClick() {
        c();
        w wVar = this.a;
        if (wVar != null) {
            wVar.a(null, true);
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderProcessGone() {
        View view = this.h;
        if (view != null) {
            removeView(view);
            this.h = null;
        }
        a(new com.pubmatic.sdk.video.a(602, "End-card failed to render."));
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void render(com.pubmatic.sdk.common.base.c cVar) {
        if (cVar == null) {
            b();
        } else {
            POBLog.debug("POBMraidEndCardView", "Suitable end-card found.", new Object[0]);
            if (!com.pubmatic.sdk.common.network.i.isNetworkAvailable(getContext())) {
                a(new com.pubmatic.sdk.video.a(602, "End-card failed to render due to network connectivity."));
            } else if (!renderMRAIDView(cVar)) {
                a(new com.pubmatic.sdk.video.a(604, "No supported resource found for end-card."));
            }
        }
        e();
    }

    public boolean renderMRAIDView(@NonNull com.pubmatic.sdk.common.base.c cVar) {
        com.pubmatic.sdk.webrendering.mraid.e eVar;
        this.c = com.pubmatic.sdk.webrendering.mraid.e.createInstance(getContext(), DTBAdSize.AAX_INTERSTITIAL_AD_SIZE, hashCode());
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(cVar.getRenderableContent()) || (eVar = this.c) == null) {
            return false;
        }
        eVar.setAdRendererListener(this);
        this.c.setBaseURL(com.pubmatic.sdk.common.i.getSdkConfig().isRequestSecureCreative() ? "https://ow.pubmatic.com/openrtb/2.5" : "http://ow.pubmatic.com/openrtb/2.5");
        this.c.renderAd(cVar);
        return true;
    }

    public void setFSCEnabled(boolean z) {
        setOnClickListener(z ? this : null);
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setLearnMoreTitle(@NonNull String str) {
        this.b = str;
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setListener(w wVar) {
        this.a = wVar;
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setOnSkipOptionUpdateListener(com.pubmatic.sdk.webrendering.ui.o oVar) {
        this.f = oVar;
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setSkipAfter(int i) {
        this.d = i;
    }

    private void a() {
        POBLog.debug("POBMraidEndCardView", "Rendering Learn More button on end-card.", new Object[0]);
        Resources resources = getResources();
        View viewA = F.a(getContext(), com.pubmatic.sdk.video.h.pob_learn_more_btn, this.b, resources.getColor(com.pubmatic.sdk.video.e.pob_controls_background_color));
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_height));
        layoutParams.gravity = 17;
        addView(viewA, layoutParams);
        viewA.setOnClickListener(this);
    }

    private void a(@NonNull com.pubmatic.sdk.video.a aVar) {
        w wVar = this.a;
        if (wVar != null) {
            wVar.a(aVar);
        }
        b();
    }

    private void a(boolean z) {
        com.pubmatic.sdk.webrendering.ui.o oVar = this.f;
        if (oVar != null) {
            oVar.onSkipOptionUpdate(z);
        }
    }
}
