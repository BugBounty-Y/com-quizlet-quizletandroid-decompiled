package com.pubmatic.sdk.webrendering.ui;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class m extends FrameLayout {

    @NonNull
    private final ImageView a;
    private int b;
    private o c;
    private e d;
    private boolean e;
    private com.pubmatic.sdk.common.viewability.i f;
    private n g;

    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (view.getId() == com.pubmatic.sdk.webrendering.e.pob_close_btn) {
                if (m.this.g != null) {
                    m.this.g.onClose();
                }
            } else if (view.getId() == com.pubmatic.sdk.webrendering.e.pob_forward_btn) {
                com.pubmatic.sdk.webrendering.a.updateSkipButtonToCloseButton((ImageButton) view);
                if (m.this.g != null) {
                    m.this.g.onForward();
                }
                view.bringToFront();
            }
        }
    }

    public class b implements d {
        public b() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.d
        public void onTimerExhausted() {
            m.this.a();
        }
    }

    public m(@NonNull Context context, boolean z) {
        super(context);
        if (z) {
            this.a = com.pubmatic.sdk.webrendering.a.createSkipButton(context, com.pubmatic.sdk.webrendering.e.pob_forward_btn, com.pubmatic.sdk.webrendering.d.pob_ic_forward_24);
        } else {
            this.a = com.pubmatic.sdk.webrendering.a.createSkipButton(context, com.pubmatic.sdk.webrendering.e.pob_close_btn, com.pubmatic.sdk.webrendering.d.pob_ic_close_black_24dp);
        }
    }

    public void configureSkippability(int i) {
        this.b = i;
    }

    @NonNull
    public ImageView getSkipBtn() {
        return this.a;
    }

    public void onAdViewClicked() {
        a();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        POBLog.debug("POBMraidViewContainer", "Display interstitial skipOffset: " + this.b, new Object[0]);
        com.pubmatic.sdk.common.viewability.i iVar = this.f;
        if (iVar != null) {
            iVar.addFriendlyObstructions(this.a, com.pubmatic.sdk.common.viewability.h.CLOSE_AD);
        }
        if (!this.e || this.b <= 0) {
            a();
            return;
        }
        this.a.setVisibility(4);
        e eVar = new e(getContext(), this.b);
        this.d = eVar;
        eVar.setTimerExhaustedListener(new b());
        addView(this.d);
        com.pubmatic.sdk.common.viewability.i iVar2 = this.f;
        if (iVar2 != null) {
            iVar2.addFriendlyObstructions(this.d, com.pubmatic.sdk.common.viewability.h.OTHER);
        }
    }

    public void setEnableSkipTimer(boolean z) {
        this.e = z;
    }

    public void setMraidViewContainerListener(n nVar) {
        this.g = nVar;
    }

    public void setObstructionUpdateListener(com.pubmatic.sdk.common.viewability.i iVar) {
        this.f = iVar;
    }

    public void setSkipOptionUpdateListener(o oVar) {
        this.c = oVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        e eVar = this.d;
        if (eVar == null || eVar.getParent() == null) {
            return;
        }
        removeView(this.d);
        this.a.setVisibility(0);
        a(true);
    }

    public m(@NonNull Context context, @NonNull ViewGroup viewGroup, boolean z) {
        this(context, z);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        layoutParams.gravity = 17;
        layoutParams.setMargins(0, 0, 0, 0);
        addView(viewGroup, layoutParams);
        this.a.setOnClickListener(new a());
        addView(this.a);
    }

    private void a(boolean z) {
        o oVar = this.c;
        if (oVar != null) {
            oVar.onSkipOptionUpdate(z);
        }
    }
}
