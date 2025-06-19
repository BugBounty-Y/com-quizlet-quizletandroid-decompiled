package com.quizlet.features.infra.ui.feedback.sound.soundeffect;

import android.media.MediaPlayer;
import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class e implements InterfaceC1250k {
    public final com.quizlet.data.repository.classfolder.e a;
    public final com.google.android.material.floatingactionbutton.c b;
    public final kotlinx.coroutines.scheduling.e c;
    public MediaPlayer d;
    public a e;

    public e(com.quizlet.data.repository.classfolder.e soundEffectMediaPlayerCreator, com.google.android.material.floatingactionbutton.c getCurrentSoundEffectsPreferenceUseCase, kotlinx.coroutines.scheduling.e defaultDispatcher) {
        Intrinsics.checkNotNullParameter(soundEffectMediaPlayerCreator, "soundEffectMediaPlayerCreator");
        Intrinsics.checkNotNullParameter(getCurrentSoundEffectsPreferenceUseCase, "getCurrentSoundEffectsPreferenceUseCase");
        Intrinsics.checkNotNullParameter(defaultDispatcher, "defaultDispatcher");
        this.a = soundEffectMediaPlayerCreator;
        this.b = getCurrentSoundEffectsPreferenceUseCase;
        this.c = defaultDispatcher;
        E.c(defaultDispatcher);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0083, code lost:
    
        if (r8 == r1) goto L31;
     */
    /* JADX WARN: Removed duplicated region for block: B:34:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(com.quizlet.features.infra.ui.feedback.sound.soundeffect.a r7, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.features.infra.ui.feedback.sound.soundeffect.c
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.c r0 = (com.quizlet.features.infra.ui.feedback.sound.soundeffect.c) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.c r0 = new com.quizlet.features.infra.ui.feedback.sound.soundeffect.c
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L40
            if (r2 == r4) goto L34
            if (r2 != r3) goto L2c
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.e r7 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L86
        L2c:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L34:
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.a r7 = r0.k
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r5 = r8
            r8 = r7
            r7 = r2
            r2 = r5
            goto L59
        L40:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            r0.j = r6
            r0.k = r7
            r0.n = r4
            com.google.android.material.floatingactionbutton.c r8 = r6.b
            java.lang.Object r8 = r8.b
            com.quizlet.local.datastore.models.metering.i r8 = (com.quizlet.local.datastore.models.metering.i) r8
            java.lang.Object r8 = r8.b(r0)
            if (r8 != r1) goto L56
            goto L85
        L56:
            r2 = r8
            r8 = r7
            r7 = r6
        L59:
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 != 0) goto L64
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        L64:
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.a r2 = r7.e
            boolean r2 = kotlin.jvm.internal.Intrinsics.b(r2, r8)
            if (r2 != 0) goto L86
            r0.j = r7
            r2 = 0
            r0.k = r2
            r0.n = r3
            com.quizlet.features.infra.ui.feedback.sound.soundeffect.d r3 = new com.quizlet.features.infra.ui.feedback.sound.soundeffect.d
            r3.<init>(r7, r8, r2)
            kotlinx.coroutines.scheduling.e r8 = r7.c
            java.lang.Object r8 = kotlinx.coroutines.E.J(r8, r3, r0)
            if (r8 != r1) goto L81
            goto L83
        L81:
            kotlin.Unit r8 = kotlin.Unit.a
        L83:
            if (r8 != r1) goto L86
        L85:
            return r1
        L86:
            android.media.MediaPlayer r7 = r7.d
            if (r7 == 0) goto L8d
            r7.start()
        L8d:
            kotlin.Unit r7 = kotlin.Unit.a
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.infra.ui.feedback.sound.soundeffect.e.a(com.quizlet.features.infra.ui.feedback.sound.soundeffect.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J owner) throws IllegalStateException {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        this.e = null;
        MediaPlayer mediaPlayer = this.d;
        if (mediaPlayer != null) {
            mediaPlayer.stop();
        }
        MediaPlayer mediaPlayer2 = this.d;
        if (mediaPlayer2 != null) {
            mediaPlayer2.release();
        }
        this.d = null;
    }
}
