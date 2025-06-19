package com.quizlet.shared.models.api.srs;

import androidx.compose.animation.d0;
import assistantMode.enums.EnumC1452f;
import assistantMode.enums.m;
import assistantMode.enums.u;
import assistantMode.refactored.a;
import assistantMode.refactored.enums.l;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class LatestAnswer {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final l b;
    public final u c;
    public final int d;
    public final Integer e;
    public final m f;
    public final m g;
    public final long h;
    public final EnumC1452f i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return LatestAnswer$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ LatestAnswer(int i, long j, l lVar, u uVar, int i2, Integer num, m mVar, m mVar2, long j2, EnumC1452f enumC1452f) {
        if (495 != (i & 495)) {
            AbstractC5047c0.k(i, 495, LatestAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = uVar;
        this.d = i2;
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = num;
        }
        this.f = mVar;
        this.g = mVar2;
        this.h = j2;
        this.i = enumC1452f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LatestAnswer)) {
            return false;
        }
        LatestAnswer latestAnswer = (LatestAnswer) obj;
        return this.a == latestAnswer.a && this.b == latestAnswer.b && this.c == latestAnswer.c && this.d == latestAnswer.d && Intrinsics.b(this.e, latestAnswer.e) && this.f == latestAnswer.f && this.g == latestAnswer.g && this.h == latestAnswer.h && this.i == latestAnswer.i;
    }

    public final int hashCode() {
        int iB = d0.b(this.d, (this.c.hashCode() + ((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31)) * 31, 31);
        Integer num = this.e;
        return this.i.hashCode() + d0.d(a.e(this.g, a.e(this.f, (iB + (num == null ? 0 : num.hashCode())) * 31, 31), 31), 31, this.h);
    }

    public final String toString() {
        return "LatestAnswer(studiableItemId=" + this.a + ", studiableItemType=" + this.b + ", studyModeType=" + this.c + ", answerType=" + this.d + ", questionType=" + this.e + ", promptSide=" + this.f + ", answerSide=" + this.g + ", answerTimestamp=" + this.h + ", correctness=" + this.i + ")";
    }
}
