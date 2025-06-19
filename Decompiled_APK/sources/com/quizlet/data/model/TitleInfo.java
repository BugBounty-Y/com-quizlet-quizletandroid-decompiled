package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class TitleInfo extends R1 {
    public final String a;
    public final EnumC4175w b;
    public final String c;

    public TitleInfo(String uuid, EnumC4175w status, String str) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.a = uuid;
        this.b = status;
        this.c = str;
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
        if (!(obj instanceof TitleInfo)) {
            return false;
        }
        TitleInfo titleInfo = (TitleInfo) obj;
        return Intrinsics.b(this.a, titleInfo.a) && this.b == titleInfo.b && Intrinsics.b(this.c, titleInfo.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        String str = this.c;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TitleInfo(uuid=");
        sb.append(this.a);
        sb.append(", status=");
        sb.append(this.b);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    public /* synthetic */ TitleInfo(String str, EnumC4175w enumC4175w, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, enumC4175w, (i & 4) != 0 ? null : str2);
    }
}
