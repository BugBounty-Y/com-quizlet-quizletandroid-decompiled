package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import android.content.res.AssetFileDescriptor;
import android.content.res.Resources;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.quizlet.features.match.data.AbstractC4368y;
import com.quizlet.features.match.data.V;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public g j;
    public AssetFileDescriptor k;
    public int l;
    public final /* synthetic */ AbstractC4368y m;
    public final /* synthetic */ g n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(AbstractC4368y abstractC4368y, g gVar, h hVar) {
        super(2, hVar);
        this.m = abstractC4368y;
        this.n = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Resources.NotFoundException {
        g gVar;
        AssetFileDescriptor assetFileDescriptor;
        Throwable th;
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        if (i == 0) {
            Z.e(obj);
            AbstractC4368y state = this.m;
            if (state != null) {
                gVar = this.n;
                com.quizlet.features.match.audio.a aVar = gVar.f;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(state, "state");
                AssetFileDescriptor assetFileDescriptorOpenRawResourceFd = aVar.a.getResources().openRawResourceFd(state instanceof V ? R.raw.match_game_music : R.raw.match_celebration_music);
                Intrinsics.checkNotNullExpressionValue(assetFileDescriptorOpenRawResourceFd, "openRawResourceFd(...)");
                try {
                    com.quizlet.quizletandroid.audio.players.c cVar = gVar.e;
                    this.j = gVar;
                    this.k = assetFileDescriptorOpenRawResourceFd;
                    this.l = 1;
                    cVar.getClass();
                    kotlinx.coroutines.scheduling.e eVar = O.a;
                    Object objJ = E.J(kotlinx.coroutines.scheduling.d.b, new com.quizlet.quizletandroid.audio.players.a(cVar, assetFileDescriptorOpenRawResourceFd, null), this);
                    if (objJ != obj2) {
                        objJ = Unit.a;
                    }
                    if (objJ == obj2) {
                        return obj2;
                    }
                    assetFileDescriptor = assetFileDescriptorOpenRawResourceFd;
                } catch (Throwable th2) {
                    assetFileDescriptor = assetFileDescriptorOpenRawResourceFd;
                    th = th2;
                    throw th;
                }
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        assetFileDescriptor = this.k;
        gVar = this.j;
        try {
            Z.e(obj);
        } catch (Throwable th3) {
            th = th3;
            try {
                throw th;
            } catch (Throwable th4) {
                AbstractC3336f.c(assetFileDescriptor, th);
                throw th4;
            }
        }
        gVar.d.a.edit().putBoolean("PREF_MATCH_PLAY_AUDIO", true).apply();
        Unit unit = Unit.a;
        AbstractC3336f.c(assetFileDescriptor, null);
        return Unit.a;
    }
}
