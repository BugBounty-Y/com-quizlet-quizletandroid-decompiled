package com.pubmatic.sdk.video.player;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface u {
    void onBufferUpdate(int i);

    void onClick();

    void onCompletion();

    void onFailure(int i, @NonNull String str);

    void onMute(boolean z);

    void onPause();

    void onProgressUpdate(int i);

    void onReadyToPlay(@NonNull v vVar);

    void onResume();

    void onStart();
}
