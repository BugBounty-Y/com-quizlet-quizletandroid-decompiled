package com.pubmatic.sdk.video.player;

import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* renamed from: com.pubmatic.sdk.video.player.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public interface InterfaceC4066a {
    FrameLayout getView();

    void render(com.pubmatic.sdk.common.base.c cVar);

    void setLearnMoreTitle(@NonNull String str);

    void setListener(w wVar);

    void setOnSkipOptionUpdateListener(com.pubmatic.sdk.webrendering.ui.o oVar);

    void setSkipAfter(int i);
}
