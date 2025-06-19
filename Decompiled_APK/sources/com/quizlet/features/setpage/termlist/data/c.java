package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_common.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends C {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;

    public c(long j, String str, String str2, boolean z) {
        this.a = j;
        this.b = str;
        this.c = str2;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return Boolean.hashCode(this.d) + ((iHashCode2 + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AudioIconClick(termId=");
        sb.append(this.a);
        sb.append(", wordAudioUrl=");
        sb.append(this.b);
        sb.append(", definitionAudioUrl=");
        sb.append(this.c);
        sb.append(", isAudioPlaying=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
