package com.quizlet.quizletandroid.audio.players;

import android.media.MediaPlayer;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.internal.operators.observable.m0;
import java.io.File;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public File a;
    public MediaPlayer b;
    public io.reactivex.rxjava3.internal.operators.completable.d c;
    public final io.reactivex.rxjava3.subjects.d d;
    public io.reactivex.rxjava3.disposables.b e;

    public h() {
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.d = dVarZ;
    }

    public final void a() {
        io.reactivex.rxjava3.disposables.b bVarU = this.e;
        if (bVarU == null) {
            TimeUnit timeUnit = TimeUnit.SECONDS;
            io.reactivex.rxjava3.subjects.d dVar = this.d;
            dVar.getClass();
            o oVar = io.reactivex.rxjava3.schedulers.e.b;
            Objects.requireNonNull(timeUnit, "unit is null");
            Objects.requireNonNull(oVar, "scheduler is null");
            bVarU = new m0(dVar, oVar, 2).u(g.a, new com.quizlet.analytics.marketing.e(this, 20), io.reactivex.rxjava3.internal.functions.d.c);
            Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        }
        this.e = bVarU;
    }

    public final void b() {
        timber.log.c.a.g("Releasing MediaPlayer instance due to inactivity...", new Object[0]);
        MediaPlayer mediaPlayer = this.b;
        if (mediaPlayer != null) {
            mediaPlayer.reset();
        }
        MediaPlayer mediaPlayer2 = this.b;
        if (mediaPlayer2 != null) {
            mediaPlayer2.release();
        }
        this.b = null;
        io.reactivex.rxjava3.disposables.b bVar = this.e;
        if (bVar != null) {
            bVar.dispose();
        }
    }

    public final boolean c() {
        this.d.b(Unit.a);
        io.reactivex.rxjava3.internal.operators.completable.d dVar = this.c;
        if (dVar != null) {
            dVar.onComplete();
        }
        this.c = null;
        this.a = null;
        MediaPlayer mediaPlayer = this.b;
        if (mediaPlayer == null || !mediaPlayer.isPlaying()) {
            a();
            return false;
        }
        MediaPlayer mediaPlayer2 = this.b;
        if (mediaPlayer2 != null) {
            mediaPlayer2.stop();
        }
        timber.log.c.a.g("Stopped MediaPlayer playback.", new Object[0]);
        a();
        return true;
    }
}
