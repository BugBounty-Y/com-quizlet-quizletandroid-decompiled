package com.quizlet.shared.models.api.srs;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.a;
import assistantMode.refactored.enums.j;
import assistantMode.refactored.enums.l;
import com.quizlet.shared.enums.n;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class StudiableItemProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] k = {null, null, null, null, null, null, null, new C5048d(MemoryScore$$serializer.INSTANCE, 0), null, null};
    public final long a;
    public final long b;
    public final j c;
    public final long d;
    public final l e;
    public final m f;
    public final m g;
    public final List h;
    public final Long i;
    public final n j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudiableItemProgress$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudiableItemProgress(int i, long j, long j2, j jVar, long j3, l lVar, m mVar, m mVar2, List list, Long l, n nVar) {
        if (767 != (i & 767)) {
            AbstractC5047c0.k(i, 767, StudiableItemProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = jVar;
        this.d = j3;
        this.e = lVar;
        this.f = mVar;
        this.g = mVar2;
        this.h = list;
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = l;
        }
        this.j = nVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableItemProgress)) {
            return false;
        }
        StudiableItemProgress studiableItemProgress = (StudiableItemProgress) obj;
        return this.a == studiableItemProgress.a && this.b == studiableItemProgress.b && this.c == studiableItemProgress.c && this.d == studiableItemProgress.d && this.e == studiableItemProgress.e && this.f == studiableItemProgress.f && this.g == studiableItemProgress.g && Intrinsics.b(this.h, studiableItemProgress.h) && Intrinsics.b(this.i, studiableItemProgress.i) && this.j == studiableItemProgress.j;
    }

    public final int hashCode() {
        int iF = d0.f(a.e(this.g, a.e(this.f, (this.e.hashCode() + d0.d((this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b)) * 31, 31, this.d)) * 31, 31), 31), 31, this.h);
        Long l = this.i;
        return this.j.hashCode() + ((iF + (l == null ? 0 : l.hashCode())) * 31);
    }

    public final String toString() {
        return "StudiableItemProgress(personId=" + this.a + ", studiableContainerId=" + this.b + ", studiableContainerType=" + this.c + ", studiableItemId=" + this.d + ", studiableItemType=" + this.e + ", promptSide=" + this.f + ", answerSide=" + this.g + ", memoryScores=" + this.h + ", nextDueDate=" + this.i + ", status=" + this.j + ")";
    }
}
