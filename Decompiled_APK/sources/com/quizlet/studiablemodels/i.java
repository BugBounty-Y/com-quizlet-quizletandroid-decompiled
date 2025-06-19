package com.quizlet.studiablemodels;

import com.quizlet.generated.enums.C4511p1;
import com.quizlet.generated.enums.EnumC4514q1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final long a;
    public final e b;
    public final e c;
    public final boolean d;
    public final String e;

    public i(long j, e word, e definition, a aVar, boolean z) {
        Intrinsics.checkNotNullParameter(word, "word");
        Intrinsics.checkNotNullParameter(definition, "definition");
        this.a = j;
        this.b = word;
        this.c = definition;
        this.d = z;
        StudiableImage studiableImage = definition.d;
        this.e = studiableImage != null ? studiableImage.a() : null;
        C4511p1 c4511p1 = EnumC4514q1.Companion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a == iVar.a && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(null, null) && this.d == iVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((((this.c.hashCode() + ((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31)) * 31) + 0) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TermShapedCard(id=");
        sb.append(this.a);
        sb.append(", word=");
        sb.append(this.b);
        sb.append(", definition=");
        sb.append(this.c);
        sb.append(", diagram=");
        sb.append((Object) null);
        sb.append(", isAudioPlaying=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
