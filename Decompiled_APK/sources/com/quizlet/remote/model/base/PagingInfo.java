package com.quizlet.remote.model.base;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.LinkedHashMap;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PagingInfo {
    public final int a;
    public final int b;
    public final String c;
    public final int d;
    public final boolean e;

    public PagingInfo(@InterfaceC4853h(name = "total") int i, @InterfaceC4853h(name = "page") int i2, @InterfaceC4853h(name = "token") String str, @InterfaceC4853h(name = "perPage") int i3) {
        this.a = i;
        this.b = i2;
        this.c = str;
        this.d = i3;
        this.e = i2 * i3 >= i;
    }

    public final LinkedHashMap a() {
        int i = this.d;
        if (i <= 0) {
            i = 200;
        }
        LinkedHashMap linkedHashMapG = V.g(new Pair("perPage", String.valueOf(i)));
        int i2 = this.b;
        if (i2 > 0) {
            linkedHashMapG.put("page", String.valueOf(i2));
        }
        String str = this.c;
        if (str != null) {
            linkedHashMapG.put("pagingToken", str);
        }
        return linkedHashMapG;
    }

    @NotNull
    public final PagingInfo copy(@InterfaceC4853h(name = "total") int i, @InterfaceC4853h(name = "page") int i2, @InterfaceC4853h(name = "token") String str, @InterfaceC4853h(name = "perPage") int i3) {
        return new PagingInfo(i, i2, str, i3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PagingInfo)) {
            return false;
        }
        PagingInfo pagingInfo = (PagingInfo) obj;
        return this.a == pagingInfo.a && this.b == pagingInfo.b && Intrinsics.b(this.c, pagingInfo.c) && this.d == pagingInfo.d;
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        String str = this.c;
        return Integer.hashCode(this.d) + ((iB + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingInfo(Page:");
        sb.append(this.b);
        sb.append(", Total:");
        sb.append(this.a);
        sb.append(", Token: ");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    public /* synthetic */ PagingInfo(int i, int i2, String str, int i3, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this((i4 & 1) != 0 ? 0 : i, (i4 & 2) != 0 ? 0 : i2, (i4 & 4) != 0 ? null : str, (i4 & 8) != 0 ? 0 : i3);
    }
}
