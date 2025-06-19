package com.pubmatic.sdk.video.player;

import android.content.Context;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public abstract class i extends FrameLayout implements u {
    public i(@NonNull Context context) {
        super(context);
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onBufferUpdate(int i) {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onClick() {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onCompletion() {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onFailure(int i, @NonNull String str) {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public abstract /* synthetic */ void onMute(boolean z);

    @Override // com.pubmatic.sdk.video.player.u
    public abstract /* synthetic */ void onPause();

    @Override // com.pubmatic.sdk.video.player.u
    public abstract /* synthetic */ void onProgressUpdate(int i);

    @Override // com.pubmatic.sdk.video.player.u
    public void onReadyToPlay(@NonNull v vVar) {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public abstract /* synthetic */ void onResume();

    @Override // com.pubmatic.sdk.video.player.u
    public abstract /* synthetic */ void onStart();

    public abstract void setVideoPlayerEvents(@NonNull s sVar);
}
