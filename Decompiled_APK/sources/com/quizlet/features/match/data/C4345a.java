package com.quizlet.features.match.data;

import com.quizlet.studiablemodels.StudiableAudio;
import com.quizlet.studiablemodels.StudiableImage;
import com.quizlet.studiablemodels.StudiableText;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.match.data.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4345a extends AbstractC4355k {
    public final int b;
    public final StudiableText c;
    public final StudiableImage d;
    public final StudiableAudio e;

    public C4345a(int i, StudiableText studiableText, StudiableImage studiableImage, StudiableAudio studiableAudio) {
        this.b = i;
        this.c = studiableText;
        this.d = studiableImage;
        this.e = studiableAudio;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4345a)) {
            return false;
        }
        C4345a c4345a = (C4345a) obj;
        return this.b == c4345a.b && Intrinsics.b(this.c, c4345a.c) && Intrinsics.b(this.d, c4345a.d) && Intrinsics.b(this.e, c4345a.e);
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.b) * 31;
        StudiableText studiableText = this.c;
        int iHashCode2 = (iHashCode + (studiableText == null ? 0 : studiableText.hashCode())) * 31;
        StudiableImage studiableImage = this.d;
        int iHashCode3 = (iHashCode2 + (studiableImage == null ? 0 : studiableImage.hashCode())) * 31;
        StudiableAudio studiableAudio = this.e;
        return iHashCode3 + (studiableAudio != null ? studiableAudio.a.hashCode() : 0);
    }

    public final String toString() {
        return "DefaultMatchCardItem(id=" + this.b + ", text=" + this.c + ", image=" + this.d + ", audio=" + this.e + ")";
    }
}
