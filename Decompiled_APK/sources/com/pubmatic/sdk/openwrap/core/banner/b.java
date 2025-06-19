package com.pubmatic.sdk.openwrap.core.banner;

import android.view.View;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.base.c;
import com.pubmatic.sdk.common.base.d;
import com.pubmatic.sdk.common.g;
import com.pubmatic.sdk.common.h;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.openwrap.core.z;

/* loaded from: classes2.dex */
public class b implements com.pubmatic.sdk.common.ui.a, d, com.pubmatic.sdk.video.renderer.d {
    private com.pubmatic.sdk.common.ui.a a;
    private d b;

    @NonNull
    private final a c;

    public b(@NonNull a aVar) {
        this.c = aVar;
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void destroy() {
        com.pubmatic.sdk.common.ui.a aVar = this.a;
        if (aVar != null) {
            aVar.destroy();
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void invalidateExpiration() {
    }

    @Override // com.pubmatic.sdk.video.renderer.d
    public void notifyAdEvent(@NonNull g gVar) {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdExpired() {
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdImpression() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdImpression();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStarted() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdInteractionStarted();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdInteractionStopped() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdInteractionStopped();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdReadyToRefresh(int i) {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdReadyToRefresh(i);
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRender(@NonNull View view, c cVar) {
        view.setId(z.pob_ow_adview);
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRender(view, cVar);
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdRenderingFailed(@NonNull h hVar) {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRenderingFailed(hVar);
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onAdUnload() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdUnload();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onLeavingApplication() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onLeavingApplication();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderAdClick() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onRenderAdClick();
        }
    }

    @Override // com.pubmatic.sdk.common.base.d
    public void onRenderProcessGone() {
        d dVar = this.b;
        if (dVar != null) {
            dVar.onRenderProcessGone();
        }
    }

    @Override // com.pubmatic.sdk.video.renderer.d
    public void onSkipOptionUpdate(boolean z) {
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void renderAd(@NonNull c cVar) {
        POBLog.debug("POBBannerRenderer", "Rendering onStart in POBBannerRenderer", new Object[0]);
        if (cVar.getRenderableContent() != null) {
            com.pubmatic.sdk.common.ui.a aVarBuild = this.c.build(cVar, hashCode());
            this.a = aVarBuild;
            if (aVarBuild != null) {
                aVarBuild.setAdRendererListener(this);
                this.a.renderAd(cVar);
                return;
            }
        }
        d dVar = this.b;
        if (dVar != null) {
            dVar.onAdRenderingFailed(new h(1009, "Rendering failed for descriptor: " + cVar));
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void setAdRendererListener(d dVar) {
        this.b = dVar;
    }
}
