package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class o extends r {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final boolean e;
    public final boolean f;
    public final boolean g;
    public final boolean h;
    public final m i;
    public final b j;

    public o(int i, int i2, int i3, int i4, boolean z, boolean z2, boolean z3, boolean z4, m mVar, b bVar) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = z;
        this.f = z2;
        this.g = z3;
        this.h = z4;
        this.i = mVar;
        this.j = bVar;
    }

    public static o a(o oVar, int i, int i2, int i3, int i4, boolean z, boolean z2, boolean z3, boolean z4, m mVar, b bVar, int i5) {
        if ((i5 & 1) != 0) {
            i = oVar.a;
        }
        int i6 = i;
        if ((i5 & 2) != 0) {
            i2 = oVar.b;
        }
        int i7 = i2;
        if ((i5 & 4) != 0) {
            i3 = oVar.c;
        }
        int i8 = i3;
        if ((i5 & 8) != 0) {
            i4 = oVar.d;
        }
        return new o(i6, i7, i8, i4, (i5 & 16) != 0 ? oVar.e : z, (i5 & 32) != 0 ? oVar.f : z2, (i5 & 64) != 0 ? oVar.g : z3, (i5 & 128) != 0 ? oVar.h : z4, (i5 & 256) != 0 ? oVar.i : mVar, (i5 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0 ? oVar.j : bVar);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && this.b == oVar.b && this.c == oVar.c && this.d == oVar.d && this.e == oVar.e && this.f == oVar.f && this.g == oVar.g && this.h == oVar.h && this.i == oVar.i && Intrinsics.b(this.j, oVar.j);
    }

    public final int hashCode() {
        int iG = d0.g(d0.g(d0.g(d0.g(d0.b(this.d, d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31), 31), 31, this.e), 31, this.f), 31, this.g), 31, this.h);
        m mVar = this.i;
        int iHashCode = (iG + (mVar == null ? 0 : mVar.hashCode())) * 31;
        b bVar = this.j;
        return iHashCode + (bVar != null ? bVar.hashCode() : 0);
    }

    public final String toString() {
        return "Content(stillLearningCount=" + this.a + ", knowCount=" + this.b + ", numCardsInCycle=" + this.c + ", numCardsSeenInCycle=" + this.d + ", isSortingEnabled=" + this.e + ", isAutoPlayEnabled=" + this.f + ", isAudioPlaying=" + this.g + ", canUndo=" + this.h + ", onboardingText=" + this.i + ", card=" + this.j + ")";
    }
}
