package com.quizlet.features.setpage.termlist.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements k {
    public final long a;
    public final com.quizlet.features.infra.models.a b;
    public final com.quizlet.features.infra.models.a c;
    public final String d;
    public final String e;
    public final String f;
    public final boolean g;

    public j(long j, com.quizlet.features.infra.models.a word, com.quizlet.features.infra.models.a aVar, String str, String str2, String str3, boolean z) {
        Intrinsics.checkNotNullParameter(word, "word");
        this.a = j;
        this.b = word;
        this.c = aVar;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.g = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return this.a == jVar.a && Intrinsics.b(this.b, jVar.b) && Intrinsics.b(this.c, jVar.c) && Intrinsics.b(this.d, jVar.d) && Intrinsics.b(this.e, jVar.e) && Intrinsics.b(this.f, jVar.f) && this.g == jVar.g;
    }

    @Override // com.quizlet.features.setpage.termlist.data.k
    public final long getId() {
        return this.a;
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31;
        com.quizlet.features.infra.models.a aVar = this.c;
        int iHashCode2 = (iHashCode + (aVar == null ? 0 : aVar.hashCode())) * 31;
        String str = this.d;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.e;
        int iHashCode4 = (iHashCode3 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.f;
        return Boolean.hashCode(this.g) + ((iHashCode4 + (str3 != null ? str3.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TermData(id=");
        sb.append(this.a);
        sb.append(", word=");
        sb.append(this.b);
        sb.append(", definition=");
        sb.append(this.c);
        sb.append(", imageUrl=");
        sb.append(this.d);
        sb.append(", wordAudioUrl=");
        sb.append(this.e);
        sb.append(", definitionAudioUrl=");
        sb.append(this.f);
        sb.append(", isAudioPlaying=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
