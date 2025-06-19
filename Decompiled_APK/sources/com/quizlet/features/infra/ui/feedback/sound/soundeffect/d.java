package com.quizlet.features.infra.ui.feedback.sound.soundeffect;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.MediaPlayer;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ e j;
    public final /* synthetic */ a k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, a aVar, h hVar) {
        super(2, hVar);
        this.j = eVar;
        this.k = aVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IllegalStateException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        e eVar = this.j;
        eVar.e = null;
        MediaPlayer mediaPlayer = eVar.d;
        if (mediaPlayer != null) {
            mediaPlayer.stop();
        }
        MediaPlayer mediaPlayer2 = eVar.d;
        if (mediaPlayer2 != null) {
            mediaPlayer2.release();
        }
        eVar.d = null;
        com.quizlet.data.repository.classfolder.e eVar2 = eVar.a;
        a aVar2 = this.k;
        eVar2.getClass();
        a input = aVar2;
        Intrinsics.checkNotNullParameter(input, "input");
        if (!(input instanceof b)) {
            throw new NoWhenBranchMatchedException();
        }
        MediaPlayer mediaPlayerCreate = MediaPlayer.create((Context) eVar2.b, ((b) input).a, (AudioAttributes) eVar2.c, ((AudioManager) eVar2.d).generateAudioSessionId());
        Intrinsics.checkNotNullExpressionValue(mediaPlayerCreate, "create(...)");
        eVar.d = mediaPlayerCreate;
        eVar.e = aVar2;
        return Unit.a;
    }
}
