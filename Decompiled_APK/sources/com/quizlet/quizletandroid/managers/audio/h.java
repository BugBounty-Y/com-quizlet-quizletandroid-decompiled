package com.quizlet.quizletandroid.managers.audio;

import io.reactivex.rxjava3.internal.operators.maybe.r;
import io.reactivex.rxjava3.internal.operators.maybe.u;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class h {
    public final g a;
    public final com.quizlet.quizletandroid.audio.players.h b;
    public io.reactivex.rxjava3.disposables.b c;

    public h(g audioResourceStore, com.quizlet.quizletandroid.audio.players.h rxAudioPlayer) {
        Intrinsics.checkNotNullParameter(audioResourceStore, "audioResourceStore");
        Intrinsics.checkNotNullParameter(rxAudioPlayer, "rxAudioPlayer");
        this.a = audioResourceStore;
        this.b = rxAudioPlayer;
        io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        Intrinsics.checkNotNullExpressionValue(dVar, "empty(...)");
        this.c = dVar;
    }

    public final io.reactivex.rxjava3.internal.operators.completable.a a(String url) {
        io.reactivex.rxjava3.core.g gVarA;
        Intrinsics.checkNotNullParameter(url, "url");
        com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(ttl, "ttl");
        if (StringsKt.O(url)) {
            gVarA = io.reactivex.rxjava3.internal.operators.maybe.f.a;
        } else {
            gVarA = this.a.a(new com.quizlet.qutils.data.offline.d(url, ttl, true, com.quizlet.qutils.data.offline.b.a, com.quizlet.qutils.data.offline.a.b));
        }
        io.reactivex.rxjava3.core.g gVar = gVarA;
        com.quizlet.analytics.marketing.e eVar = new com.quizlet.analytics.marketing.e(this, 22);
        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(4, new r(new u(gVar, eVar, gVar2, gVar2, io.reactivex.rxjava3.internal.functions.d.c), io.reactivex.rxjava3.android.schedulers.b.a(), 0), new com.quizlet.login.authentication.login.a(this, 6));
        Intrinsics.checkNotNullExpressionValue(aVar, "flatMapCompletable(...)");
        return aVar;
    }

    public final boolean b(boolean z) {
        if (z) {
            this.c.dispose();
            this.c = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
        }
        return this.b.c();
    }
}
