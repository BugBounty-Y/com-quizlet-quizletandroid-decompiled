package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class EssayInfo extends R1 {
    public final String a;
    public final EnumC4175w b;
    public final List c;

    public EssayInfo(String uuid, EnumC4175w status, List list) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.a = uuid;
        this.b = status;
        this.c = list;
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
        if (!(obj instanceof EssayInfo)) {
            return false;
        }
        EssayInfo essayInfo = (EssayInfo) obj;
        return Intrinsics.b(this.a, essayInfo.a) && this.b == essayInfo.b && Intrinsics.b(this.c, essayInfo.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        List list = this.c;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EssayInfo(uuid=");
        sb.append(this.a);
        sb.append(", status=");
        sb.append(this.b);
        sb.append(", essayItems=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public /* synthetic */ EssayInfo(String str, EnumC4175w enumC4175w, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, enumC4175w, (i & 4) != 0 ? null : list);
    }
}
