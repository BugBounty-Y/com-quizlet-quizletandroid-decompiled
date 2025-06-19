package com.quizlet.shared.models.api.explanations;

import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteTextbook {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Long a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final Boolean g;
    public final String h;
    public final Integer i;
    public final Boolean j;
    public final String k;
    public final Long l;
    public final Long m;
    public final Boolean n;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteTextbook$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteTextbook(int i, Long l, String str, String str2, String str3, String str4, String str5, Boolean bool, String str6, Integer num, Boolean bool2, String str7, Long l2, Long l3, Boolean bool3) {
        if (8191 != (i & 8191)) {
            AbstractC5047c0.k(i, 8191, RemoteTextbook$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = str4;
        this.f = str5;
        this.g = bool;
        this.h = str6;
        this.i = num;
        this.j = bool2;
        this.k = str7;
        this.l = l2;
        this.m = l3;
        if ((i & 8192) == 0) {
            this.n = null;
        } else {
            this.n = bool3;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteTextbook)) {
            return false;
        }
        RemoteTextbook remoteTextbook = (RemoteTextbook) obj;
        return Intrinsics.b(this.a, remoteTextbook.a) && Intrinsics.b(this.b, remoteTextbook.b) && Intrinsics.b(this.c, remoteTextbook.c) && Intrinsics.b(this.d, remoteTextbook.d) && Intrinsics.b(this.e, remoteTextbook.e) && Intrinsics.b(this.f, remoteTextbook.f) && Intrinsics.b(this.g, remoteTextbook.g) && Intrinsics.b(this.h, remoteTextbook.h) && Intrinsics.b(this.i, remoteTextbook.i) && Intrinsics.b(this.j, remoteTextbook.j) && Intrinsics.b(this.k, remoteTextbook.k) && Intrinsics.b(this.l, remoteTextbook.l) && Intrinsics.b(this.m, remoteTextbook.m) && Intrinsics.b(this.n, remoteTextbook.n);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        String str4 = this.e;
        int iHashCode5 = (iHashCode4 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.f;
        int iHashCode6 = (iHashCode5 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Boolean bool = this.g;
        int iHashCode7 = (iHashCode6 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str6 = this.h;
        int iHashCode8 = (iHashCode7 + (str6 == null ? 0 : str6.hashCode())) * 31;
        Integer num = this.i;
        int iHashCode9 = (iHashCode8 + (num == null ? 0 : num.hashCode())) * 31;
        Boolean bool2 = this.j;
        int iHashCode10 = (iHashCode9 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str7 = this.k;
        int iHashCode11 = (iHashCode10 + (str7 == null ? 0 : str7.hashCode())) * 31;
        Long l2 = this.l;
        int iHashCode12 = (iHashCode11 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.m;
        int iHashCode13 = (iHashCode12 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Boolean bool3 = this.n;
        return iHashCode13 + (bool3 != null ? bool3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteTextbook(id=");
        sb.append(this.a);
        sb.append(", isbn=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", authors=");
        sb.append(this.d);
        sb.append(", imageUrl=");
        sb.append(this.e);
        sb.append(", imageThumbnailUrl=");
        sb.append(this.f);
        sb.append(", isPremium=");
        sb.append(this.g);
        sb.append(", edition=");
        sb.append(this.h);
        sb.append(", verifiedSolutionCount=");
        sb.append(this.i);
        sb.append(", hasSolutions=");
        sb.append(this.j);
        sb.append(", webUrl=");
        sb.append(this.k);
        sb.append(", timestamp=");
        sb.append(this.l);
        sb.append(", lastModified=");
        sb.append(this.m);
        sb.append(", isDeleted=");
        return a.k(sb, this.n, ")");
    }
}
