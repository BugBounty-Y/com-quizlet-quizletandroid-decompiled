package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_common.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends C {
    public final long a;
    public final String b;
    public final boolean c;

    public f(String str, long j, boolean z) {
        this.a = j;
        this.b = str;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && this.c == fVar.c;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return Boolean.hashCode(this.c) + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SectionTextClick(termId=");
        sb.append(this.a);
        sb.append(", audioUrl=");
        sb.append(this.b);
        sb.append(", isAudioPlaying=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
