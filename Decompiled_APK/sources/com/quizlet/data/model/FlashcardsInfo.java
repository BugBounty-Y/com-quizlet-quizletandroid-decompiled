package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsInfo extends R1 {
    public final String a;
    public final EnumC4175w b;
    public final Long c;
    public final List d;

    public FlashcardsInfo(String uuid, EnumC4175w status, Long l, List list) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.a = uuid;
        this.b = status;
        this.c = l;
        this.d = list;
    }

    @Override // com.quizlet.data.model.R1
    public final EnumC4175w a() {
        return this.b;
    }

    @Override // com.quizlet.data.model.R1
    public final String b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsInfo)) {
            return false;
        }
        FlashcardsInfo flashcardsInfo = (FlashcardsInfo) obj;
        return Intrinsics.b(this.a, flashcardsInfo.a) && this.b == flashcardsInfo.b && Intrinsics.b(this.c, flashcardsInfo.c) && Intrinsics.b(this.d, flashcardsInfo.d);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        Long l = this.c;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        List list = this.d;
        return iHashCode2 + (list != null ? list.hashCode() : 0);
    }

    public final String toString() {
        return "FlashcardsInfo(uuid=" + this.a + ", status=" + this.b + ", setId=" + this.c + ", cards=" + this.d + ")";
    }

    public /* synthetic */ FlashcardsInfo(String str, EnumC4175w enumC4175w, Long l, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, enumC4175w, (i & 4) != 0 ? null : l, (i & 8) != 0 ? null : list);
    }
}
