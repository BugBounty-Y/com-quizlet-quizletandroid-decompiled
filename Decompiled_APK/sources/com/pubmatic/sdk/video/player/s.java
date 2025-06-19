package com.pubmatic.sdk.video.player;

import android.widget.FrameLayout;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface s {
    public static final int MAX_STALLING_TIMEOUT = 15000;
    public static final int MEDIA_FILE_TIMEOUT_ERROR = -1;
    public static final int RUNTIME_ERROR = -2;
    public static final q[] SUPPORTED_MEDIA_TYPE = q.values();

    void destroy();

    i getControllerView();

    int getMediaDuration();

    @NonNull
    r getPlayerState();

    boolean isMute();

    void load(@NonNull String str);

    void mute();

    void pause();

    void play();

    void playOnMute(boolean z);

    void setAutoPlayOnForeground(boolean z);

    void setControllerView(@NonNull i iVar, @NonNull FrameLayout.LayoutParams layoutParams);

    void setListener(@NonNull u uVar);

    void setPrepareTimeout(int i);

    void stop();

    void unMute();
}
