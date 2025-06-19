package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends AbstractC3146g0 {
    public final long b;
    public final D6 c;
    public final D6 d;
    public final boolean e;
    public final boolean f;
    public final com.quizlet.features.infra.models.flashcards.h g;
    public com.quizlet.qutils.string.f h;

    public b(long j, D6 front, D6 back, boolean z, boolean z2, com.quizlet.features.infra.models.flashcards.h visibleSide, com.quizlet.qutils.string.f leftOverlayText) {
        Intrinsics.checkNotNullParameter(front, "front");
        Intrinsics.checkNotNullParameter(back, "back");
        Intrinsics.checkNotNullParameter(visibleSide, "visibleSide");
        Intrinsics.checkNotNullParameter(leftOverlayText, "leftOverlayText");
        this.b = j;
        this.c = front;
        this.d = back;
        this.e = z;
        this.f = z2;
        this.g = visibleSide;
        this.h = leftOverlayText;
    }

    public static b b(b bVar, boolean z, com.quizlet.features.infra.models.flashcards.h hVar, int i) {
        long j = bVar.b;
        D6 front = bVar.c;
        D6 back = bVar.d;
        boolean z2 = bVar.e;
        if ((i & 16) != 0) {
            z = bVar.f;
        }
        boolean z3 = z;
        if ((i & 32) != 0) {
            hVar = bVar.g;
        }
        com.quizlet.features.infra.models.flashcards.h visibleSide = hVar;
        com.quizlet.qutils.string.f leftOverlayText = bVar.h;
        bVar.getClass();
        Intrinsics.checkNotNullParameter(front, "front");
        Intrinsics.checkNotNullParameter(back, "back");
        Intrinsics.checkNotNullParameter(visibleSide, "visibleSide");
        Intrinsics.checkNotNullParameter(leftOverlayText, "leftOverlayText");
        return new b(j, front, back, z2, z3, visibleSide, leftOverlayText);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.b == bVar.b && this.c.equals(bVar.c) && this.d.equals(bVar.d) && this.e == bVar.e && this.f == bVar.f && this.g == bVar.g && Intrinsics.b(this.h, bVar.h);
    }

    public final int hashCode() {
        return this.h.hashCode() + ((this.g.hashCode() + d0.g(d0.g((this.d.hashCode() + ((this.c.hashCode() + (Long.hashCode(this.b) * 31)) * 31)) * 31, 31, this.e), 31, this.f)) * 31);
    }

    public final String toString() {
        return "CardData(cardId=" + this.b + ", front=" + this.c + ", back=" + this.d + ", isSortingEnabled=" + this.e + ", isStarred=" + this.f + ", visibleSide=" + this.g + ", leftOverlayText=" + this.h + ")";
    }
}
