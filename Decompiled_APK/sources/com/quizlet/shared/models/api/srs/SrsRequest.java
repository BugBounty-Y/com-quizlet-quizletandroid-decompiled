package com.quizlet.shared.models.api.srs;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.j;
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
public final class SrsRequest {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] g = {null, null, null, null, null, new C5048d(LatestAnswer$$serializer.INSTANCE, 0)};
    public final Long a;
    public final long b;
    public final j c;
    public final String d;
    public final Long e;
    public final List f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SrsRequest$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ SrsRequest(int i, Long l, long j, j jVar, String str, Long l2, List list) {
        if (6 != (i & 6)) {
            AbstractC5047c0.k(i, 6, SrsRequest$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = l;
        }
        this.b = j;
        this.c = jVar;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = str;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = l2;
        }
        if ((i & 32) == 0) {
            this.f = null;
        } else {
            this.f = list;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SrsRequest)) {
            return false;
        }
        SrsRequest srsRequest = (SrsRequest) obj;
        return Intrinsics.b(this.a, srsRequest.a) && this.b == srsRequest.b && this.c == srsRequest.c && Intrinsics.b(this.d, srsRequest.d) && Intrinsics.b(this.e, srsRequest.e) && Intrinsics.b(this.f, srsRequest.f);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (this.c.hashCode() + d0.d((l == null ? 0 : l.hashCode()) * 31, 31, this.b)) * 31;
        String str = this.d;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        Long l2 = this.e;
        int iHashCode3 = (iHashCode2 + (l2 == null ? 0 : l2.hashCode())) * 31;
        List list = this.f;
        return iHashCode3 + (list != null ? list.hashCode() : 0);
    }

    public final String toString() {
        return "SrsRequest(personId=" + this.a + ", studiableContainerId=" + this.b + ", studiableContainerType=" + this.c + ", personTimezone=" + this.d + ", personTestDate=" + this.e + ", clientLatestAnswers=" + this.f + ")";
    }
}
