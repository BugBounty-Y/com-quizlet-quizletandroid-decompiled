package assistantMode.refactored.modelTypes.relational;

import androidx.compose.animation.d0;
import assistantMode.enums.m;
import assistantMode.refactored.a;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class RelationalStudiableCardSide {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final long b;
    public final m c;
    public final long d;
    public final long e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RelationalStudiableCardSide$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RelationalStudiableCardSide(int i, long j, long j2, m mVar, long j3, long j4) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, RelationalStudiableCardSide$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = mVar;
        this.d = j3;
        this.e = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RelationalStudiableCardSide)) {
            return false;
        }
        RelationalStudiableCardSide relationalStudiableCardSide = (RelationalStudiableCardSide) obj;
        return this.a == relationalStudiableCardSide.a && this.b == relationalStudiableCardSide.b && this.c == relationalStudiableCardSide.c && this.d == relationalStudiableCardSide.d && this.e == relationalStudiableCardSide.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + d0.d(a.e(this.c, d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelationalStudiableCardSide(id=");
        sb.append(this.a);
        sb.append(", studiableItemId=");
        sb.append(this.b);
        sb.append(", label=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", lastModified=");
        return android.support.v4.media.session.a.g(this.e, ")", sb);
    }
}
