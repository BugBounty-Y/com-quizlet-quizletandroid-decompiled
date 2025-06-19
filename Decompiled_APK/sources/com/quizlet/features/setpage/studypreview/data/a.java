package com.quizlet.features.setpage.studypreview.data;

import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.StudiableImage;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final long b;
    public final com.quizlet.features.infra.models.a c;
    public final com.quizlet.features.infra.models.a d;
    public final StudiableImage e;

    public a(long j, long j2, com.quizlet.features.infra.models.a frontTextData, com.quizlet.features.infra.models.a backTextData, StudiableImage studiableImage) {
        Intrinsics.checkNotNullParameter(frontTextData, "frontTextData");
        Intrinsics.checkNotNullParameter(backTextData, "backTextData");
        this.a = j;
        this.b = j2;
        this.c = frontTextData;
        this.d = backTextData;
        this.e = studiableImage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b)) * 31)) * 31;
        StudiableImage studiableImage = this.e;
        return iHashCode + (studiableImage == null ? 0 : studiableImage.hashCode());
    }

    public final String toString() {
        return "FlashcardData(id=" + this.a + ", localId=" + this.b + ", frontTextData=" + this.c + ", backTextData=" + this.d + ", backImage=" + this.e + ")";
    }
}
