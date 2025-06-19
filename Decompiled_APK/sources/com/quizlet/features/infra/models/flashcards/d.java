package com.quizlet.features.infra.models.flashcards;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d {
    public m a;
    public m b;
    public boolean c;
    public boolean d;
    public final boolean e;
    public boolean f;
    public boolean g;
    public long h;
    public int i;

    public d(m frontSide, m backSide, boolean z, boolean z2, boolean z3, boolean z4, boolean z5, long j, int i) {
        Intrinsics.checkNotNullParameter(frontSide, "frontSide");
        Intrinsics.checkNotNullParameter(backSide, "backSide");
        this.a = frontSide;
        this.b = backSide;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = z5;
        this.h = j;
        this.i = i;
    }

    public static d a(d dVar, m mVar, m mVar2, boolean z, boolean z2, long j, int i, int i2) {
        if ((i2 & 1) != 0) {
            mVar = dVar.a;
        }
        m frontSide = mVar;
        m backSide = (i2 & 2) != 0 ? dVar.b : mVar2;
        boolean z3 = dVar.c;
        boolean z4 = dVar.d;
        boolean z5 = (i2 & 16) != 0 ? dVar.e : z;
        boolean z6 = (i2 & 32) != 0 ? dVar.f : z2;
        boolean z7 = dVar.g;
        long j2 = (i2 & 128) != 0 ? dVar.h : j;
        int i3 = (i2 & 256) != 0 ? dVar.i : i;
        Intrinsics.checkNotNullParameter(frontSide, "frontSide");
        Intrinsics.checkNotNullParameter(backSide, "backSide");
        return new d(frontSide, backSide, z3, z4, z5, z6, z7, j2, i3);
    }

    public final c b() {
        com.quizlet.shared.usecase.studiableMetadata.a aVar = c.b;
        int i = this.i;
        aVar.getClass();
        for (c cVar : c.values()) {
            if (cVar.a == i) {
                return cVar;
            }
        }
        throw new NoSuchElementException("Array contains no element matching the predicate.");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b && this.c == dVar.c && this.d == dVar.d && this.e == dVar.e && this.f == dVar.f && this.g == dVar.g && this.h == dVar.h && this.i == dVar.i;
    }

    public final int hashCode() {
        return Integer.hashCode(this.i) + d0.d(d0.g(d0.g(d0.g(d0.g(d0.g(assistantMode.refactored.a.e(this.b, this.a.hashCode() * 31, 31), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
    }

    public final String toString() {
        return "FlashcardSettings(frontSide=" + this.a + ", backSide=" + this.b + ", isSpeakWordEnabled=" + this.c + ", isSpeakDefEnabled=" + this.d + ", isAutoPlayEnabled=" + this.e + ", isShuffleEnabled=" + this.f + ", isSelectedTermsMode=" + this.g + ", shuffleSeed=" + this.h + ", rawFlashcardMode=" + this.i + ")";
    }
}
