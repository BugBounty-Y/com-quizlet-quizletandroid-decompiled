package com.quizlet.infra.legacysyncengine.net.okhttp;

import com.quizlet.quizletandroid.audio.players.h;
import io.reactivex.rxjava3.functions.c;
import okhttp3.internal.connection.g;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.functions.c
    public final void cancel() {
        switch (this.a) {
            case 0:
                ((g) this.b).cancel();
                break;
            default:
                timber.log.c.a.g("MediaPlayer playback canceled via Disposable", new Object[0]);
                ((h) this.b).c();
                break;
        }
    }
}
