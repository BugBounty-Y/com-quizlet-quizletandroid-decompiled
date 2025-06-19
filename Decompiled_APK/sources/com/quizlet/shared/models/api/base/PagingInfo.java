package com.quizlet.shared.models.api.base;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class PagingInfo {

    @NotNull
    public static final Companion Companion = new Companion();
    public final int a;
    public final int b;
    public final int c;
    public final String d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return PagingInfo$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ PagingInfo(int i, int i2, int i3, int i4, String str) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, PagingInfo$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = i2;
        this.b = i3;
        this.c = i4;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = str;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PagingInfo)) {
            return false;
        }
        PagingInfo pagingInfo = (PagingInfo) obj;
        return this.a == pagingInfo.a && this.b == pagingInfo.b && this.c == pagingInfo.c && Intrinsics.b(this.d, pagingInfo.d);
    }

    public final int hashCode() {
        int iB = d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31);
        String str = this.d;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PagingInfo(total=");
        sb.append(this.a);
        sb.append(", page=");
        sb.append(this.b);
        sb.append(", perPage=");
        sb.append(this.c);
        sb.append(", pagingToken=");
        return a.t(sb, this.d, ")");
    }
}
