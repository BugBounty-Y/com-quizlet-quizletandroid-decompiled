package com.pubmatic.sdk.video.player;

import android.view.Surface;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface h {
    public static final int MEDIA_DISPLAY_ERROR = -108;
    public static final int MEDIA_FILE_TIMEOUT_ERROR = -1;
    public static final double PROGRESS_UPDATE_DELAY = 0.5d;

    void destroy();

    int getDuration();

    int getVideoHeight();

    int getVideoWidth();

    void onSurfaceCreated(@NonNull Surface surface);

    void onSurfaceDestroyed(@NonNull Surface surface);

    void pause();

    void setPlayerListener(@NonNull g gVar);

    void setPrepareTimeout(int i);

    void setStallTimeout(int i);

    void setVolume(int i, int i2);

    void start();

    void stop();
}
