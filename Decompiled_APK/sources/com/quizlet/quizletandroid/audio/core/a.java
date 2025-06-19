package com.quizlet.quizletandroid.audio.core;

import android.media.MediaPlayer;
import com.google.mlkit.common.sdkinternal.b;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a {
    public final b a;
    public MediaPlayer b;

    public a(b mediaPlayerFactory) {
        Intrinsics.checkNotNullParameter(mediaPlayerFactory, "mediaPlayerFactory");
        this.a = mediaPlayerFactory;
    }

    public final MediaPlayer a() {
        MediaPlayer mediaPlayer = this.b;
        if (mediaPlayer != null) {
            return mediaPlayer;
        }
        c.a.m("Initializing new MediaPlayer.", new Object[0]);
        this.a.getClass();
        MediaPlayer mediaPlayer2 = new MediaPlayer();
        this.b = mediaPlayer2;
        return mediaPlayer2;
    }

    public final void b(Function1 action) {
        Intrinsics.checkNotNullParameter(action, "action");
        synchronized (this) {
            try {
                action.invoke(a());
            } catch (IllegalStateException e) {
                c.a.e(e);
                synchronized (this) {
                    try {
                        MediaPlayer mediaPlayer = this.b;
                        if (mediaPlayer != null) {
                            mediaPlayer.release();
                        }
                        this.b = null;
                        Unit unit = Unit.a;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
            Unit unit2 = Unit.a;
        }
    }
}
