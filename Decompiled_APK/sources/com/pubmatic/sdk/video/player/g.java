package com.pubmatic.sdk.video.player;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface g {
    void onBufferUpdate(int i);

    void onCompletion();

    void onFailure(int i, @NonNull String str);

    void onPause();

    void onPrepared();

    void onProgressUpdate(int i);

    void onResume();

    void onStart();

    void onStop();
}
