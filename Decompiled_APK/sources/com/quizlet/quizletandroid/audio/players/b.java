package com.quizlet.quizletandroid.audio.players;

import android.media.MediaPlayer;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.local.datastore.preferences.C4566c0;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public final /* synthetic */ c j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        c cVar = this.j;
        cVar.a.b(new C4566c0(20));
        com.quizlet.quizletandroid.audio.core.a aVar2 = cVar.a;
        synchronized (aVar2) {
            try {
                MediaPlayer mediaPlayer = aVar2.b;
                if (mediaPlayer != null) {
                    mediaPlayer.release();
                }
                aVar2.b = null;
            } catch (Throwable th) {
                throw th;
            }
        }
        return Unit.a;
    }
}
