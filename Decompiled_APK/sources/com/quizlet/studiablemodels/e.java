package com.quizlet.studiablemodels;

import assistantMode.enums.m;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends Z4 {
    public final m b;
    public final StudiableText c;
    public final StudiableImage d;
    public final StudiableAudio e;

    public e(m side, StudiableText text, StudiableImage studiableImage, StudiableAudio studiableAudio) {
        Intrinsics.checkNotNullParameter(side, "side");
        Intrinsics.checkNotNullParameter(text, "text");
        this.b = side;
        this.c = text;
        this.d = studiableImage;
        this.e = studiableAudio;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.b == eVar.b && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d) && Intrinsics.b(this.e, eVar.e);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + (this.b.hashCode() * 31)) * 31;
        StudiableImage studiableImage = this.d;
        int iHashCode2 = (iHashCode + (studiableImage == null ? 0 : studiableImage.hashCode())) * 31;
        StudiableAudio studiableAudio = this.e;
        return iHashCode2 + (studiableAudio != null ? studiableAudio.a.hashCode() : 0);
    }

    public final String toString() {
        return "QuizletDefaultCardSide(side=" + this.b + ", text=" + this.c + ", image=" + this.d + ", audio=" + this.e + ")";
    }
}
