package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements f {
    public final long a;
    public final List b;
    public final boolean c;

    public d(long j, List audioUrls, boolean z) {
        Intrinsics.checkNotNullParameter(audioUrls, "audioUrls");
        this.a = j;
        this.b = audioUrls;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && this.c == dVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.f(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PlayAudioClicked(termId=");
        sb.append(this.a);
        sb.append(", audioUrls=");
        sb.append(this.b);
        sb.append(", isAudioPlaying=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
