package com.pubmatic.sdk.video.player;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* renamed from: com.pubmatic.sdk.video.player.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4069d extends l {
    private m c;
    private View d;

    public C4069d(@NonNull Context context) {
        super(context);
    }

    public void a(com.pubmatic.sdk.video.vastmodels.c cVar) {
        m mVar;
        if (cVar != null) {
            if (!com.pubmatic.sdk.common.network.i.isNetworkAvailable(getContext())) {
                POBLog.debug("POBIconView", "Failed to render icon due to network connectivity issue.", new Object[0]);
            } else {
                if (renderVastHTMLView(cVar) || (mVar = this.c) == null) {
                    return;
                }
                mVar.a(new com.pubmatic.sdk.video.a(com.pubmatic.sdk.video.a.UNDEFINED_ERROR, "Unable to render Icon due to invalid details."));
            }
        }
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e, com.pubmatic.sdk.webrendering.ui.k
    public void onRenderProcessGone() {
        removeAllViews();
        this.d = null;
        m mVar = this.c;
        if (mVar != null) {
            mVar.a(new com.pubmatic.sdk.video.a(com.pubmatic.sdk.video.a.UNDEFINED_ERROR, "Failed to render icon."));
        }
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewClicked(String str) {
        if (this.c == null || str == null) {
            return;
        }
        if ("https://obplaceholder.click.com/".contentEquals(str)) {
            this.c.a((String) null);
        } else {
            this.c.a(str);
        }
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewRendered(@NonNull View view) {
        this.d = view;
        if (getChildCount() == 0) {
            m mVar = this.c;
            if (mVar != null) {
                mVar.a();
            }
            FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
            layoutParams.gravity = 17;
            addView(view, layoutParams);
        }
    }

    @Override // com.pubmatic.sdk.video.player.l, com.pubmatic.sdk.common.ui.e
    public void onViewRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
        m mVar = this.c;
        if (mVar != null) {
            mVar.a(new com.pubmatic.sdk.video.a(com.pubmatic.sdk.video.a.UNDEFINED_ERROR, "Failed to render icon."));
        }
    }

    public void setListener(@NonNull m mVar) {
        this.c = mVar;
    }
}
