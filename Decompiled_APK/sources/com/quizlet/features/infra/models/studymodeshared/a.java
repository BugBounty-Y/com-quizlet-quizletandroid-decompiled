package com.quizlet.features.infra.models.studymodeshared;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final com.quizlet.features.infra.models.a a;
    public final String b;
    public final String c;
    public final String d;
    public final boolean e;

    public a(com.quizlet.features.infra.models.a aVar, String str, String str2, String str3, boolean z) {
        this.a = aVar;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && this.e == aVar.e;
    }

    public final int hashCode() {
        com.quizlet.features.infra.models.a aVar = this.a;
        int iHashCode = (aVar == null ? 0 : aVar.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        return Boolean.hashCode(this.e) + ((iHashCode3 + (str3 != null ? str3.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ChoiceViewData(contentTextData=");
        sb.append(this.a);
        sb.append(", imageUrl=");
        sb.append(this.b);
        sb.append(", largeImageUrl=");
        sb.append(this.c);
        sb.append(", audioUrl=");
        sb.append(this.d);
        sb.append(", shouldPlayAudio=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
