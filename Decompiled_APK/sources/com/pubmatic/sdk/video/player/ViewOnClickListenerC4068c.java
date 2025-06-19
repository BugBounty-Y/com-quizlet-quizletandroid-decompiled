package com.pubmatic.sdk.video.player;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* renamed from: com.pubmatic.sdk.video.player.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class ViewOnClickListenerC4068c extends l implements InterfaceC4066a, View.OnClickListener {
    private w c;
    private String d;
    private com.pubmatic.sdk.common.base.c e;
    private View f;

    /* renamed from: com.pubmatic.sdk.video.player.c$a */
    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (ViewOnClickListenerC4068c.this.c != null) {
                ViewOnClickListenerC4068c.this.c.b();
            }
        }
    }

    public ViewOnClickListenerC4068c(@NonNull Context context) {
        super(context);
        setBackgroundColor(getResources().getColor(R.color.black));
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public FrameLayout getView() {
        return this;
    }

    @Override // android.view.View.OnClickListener
    public void onClick(View view) {
        w wVar;
        if (this.e != null || (wVar = this.c) == null) {
            return;
        }
        wVar.b();
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e, com.pubmatic.sdk.webrendering.ui.k
    public void onRenderProcessGone() {
        View view = this.f;
        if (view != null) {
            removeView(view);
            this.f = null;
        }
        a(new com.pubmatic.sdk.video.a(602, "End-card failed to render."));
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewClicked(String str) {
        if (this.c != null) {
            if (str == null || !"https://obplaceholder.click.com/".contentEquals(str)) {
                this.c.a(str, false);
            } else {
                this.c.a(null, false);
            }
        }
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewRendered(@NonNull View view) {
        this.f = view;
        if (getChildCount() != 0 || this.e == null) {
            return;
        }
        w wVar = this.c;
        if (wVar != null) {
            wVar.a();
        }
        C4067b.updateEndCardView(view, this, this.e);
        addView(view);
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
        a(new com.pubmatic.sdk.video.a(602, "End-card failed to render."));
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void render(com.pubmatic.sdk.common.base.c cVar) {
        this.e = cVar;
        if (cVar == null) {
            a();
            return;
        }
        POBLog.debug("POBEndCardView", "Suitable end-card found.", new Object[0]);
        if (!com.pubmatic.sdk.common.network.i.isNetworkAvailable(getContext())) {
            a(new com.pubmatic.sdk.video.a(602, "End-card failed to render due to network connectivity."));
        } else {
            if (renderVastHTMLView(cVar)) {
                return;
            }
            a(new com.pubmatic.sdk.video.a(604, "No supported resource found for end-card."));
        }
    }

    public void setFSCEnabled(boolean z) {
        setOnClickListener(z ? this : null);
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setLearnMoreTitle(@NonNull String str) {
        this.d = str;
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setListener(w wVar) {
        this.c = wVar;
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setOnSkipOptionUpdateListener(com.pubmatic.sdk.webrendering.ui.o oVar) {
    }

    @Override // com.pubmatic.sdk.video.player.InterfaceC4066a
    public void setSkipAfter(int i) {
    }

    private void a() {
        POBLog.debug("POBEndCardView", "Rendering Learn More button on end-card.", new Object[0]);
        Resources resources = getResources();
        setBackgroundColor(resources.getColor(R.color.transparent));
        View viewA = F.a(getContext(), com.pubmatic.sdk.video.h.pob_learn_more_btn, this.d, resources.getColor(com.pubmatic.sdk.video.e.pob_controls_background_color));
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_height));
        layoutParams.gravity = 81;
        layoutParams.bottomMargin = resources.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_end_card_learn_more__bottom_margin);
        addView(viewA, layoutParams);
        viewA.setOnClickListener(new a());
    }

    private void a(@NonNull com.pubmatic.sdk.video.a aVar) {
        w wVar = this.c;
        if (wVar != null) {
            wVar.a(aVar);
        }
        a();
    }
}
