package com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4761c {
    public final String a;

    public C4761c(String audioUrl) {
        Intrinsics.checkNotNullParameter(audioUrl, "audioUrl");
        this.a = audioUrl;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4761c) && Intrinsics.b(this.a, ((C4761c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PlayAudioClicked(audioUrl="), this.a, ")");
    }
}
