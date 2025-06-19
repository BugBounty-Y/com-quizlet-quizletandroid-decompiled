package com.quizlet.shared.models.api.srs;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.a;
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
public final class SrsResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h = {new C5048d(StudiableItemProgress$$serializer.INSTANCE, 0), null, null, new C5048d(MemoryScore$$serializer.INSTANCE, 0), null, null, null};
    public final List a;
    public final String b;
    public final m c;
    public final List d;
    public final int e;
    public final int f;
    public final int g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SrsResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ SrsResponse(int i, List list, String str, m mVar, List list2, int i2, int i3, int i4) {
        if (127 != (i & 127)) {
            AbstractC5047c0.k(i, 127, SrsResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = str;
        this.c = mVar;
        this.d = list2;
        this.e = i2;
        this.f = i3;
        this.g = i4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SrsResponse)) {
            return false;
        }
        SrsResponse srsResponse = (SrsResponse) obj;
        return Intrinsics.b(this.a, srsResponse.a) && Intrinsics.b(this.b, srsResponse.b) && this.c == srsResponse.c && Intrinsics.b(this.d, srsResponse.d) && this.e == srsResponse.e && this.f == srsResponse.f && this.g == srsResponse.g;
    }

    public final int hashCode() {
        return Integer.hashCode(this.g) + d0.b(this.f, d0.b(this.e, d0.f(a.e(this.c, d0.e(this.a.hashCode() * 31, 31, this.b), 31), 31, this.d), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SrsResponse(studiableContainerProgress=");
        sb.append(this.a);
        sb.append(", apiVersion=");
        sb.append(this.b);
        sb.append(", studiableContainerPromptSide=");
        sb.append(this.c);
        sb.append(", studiableContainerScores=");
        sb.append(this.d);
        sb.append(", studiableContainerTotalItemsDue=");
        sb.append(this.e);
        sb.append(", studiableContainerTotalItemsNotDue=");
        sb.append(this.f);
        sb.append(", studiableContainerTotalItemsNotStudied=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}
