package com.pubmatic.sdk.video.player;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.video.vastmodels.l;

/* loaded from: classes2.dex */
public interface o {
    void onClose();

    void onEndCardWillLeaveApp();

    void onFailedToPlay(@NonNull com.pubmatic.sdk.common.h hVar);

    void onIndustryIconClick(String str);

    void onOpenLandingPage(String str);

    void onPlaybackCompleted(float f);

    void onReadyToPlay(com.pubmatic.sdk.video.vastmodels.j jVar, float f);

    void onSkip();

    void onVideoEventOccurred(@NonNull l.b bVar);

    void onVideoStarted(float f, float f2);

    void shouldForwardClickEvent();
}
