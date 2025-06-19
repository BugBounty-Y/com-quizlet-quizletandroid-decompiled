package assistantMode.refactored.modelTypes.relational;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import assistantMode.refactored.enums.l;
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
public final class RelationalStudiableItem {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final l b;
    public final long c;
    public final long d;
    public final long e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RelationalStudiableItem$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RelationalStudiableItem(int i, long j, l lVar, long j2, long j3, long j4) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, RelationalStudiableItem$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = lVar;
        this.c = j2;
        this.d = j3;
        this.e = j4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RelationalStudiableItem)) {
            return false;
        }
        RelationalStudiableItem relationalStudiableItem = (RelationalStudiableItem) obj;
        return this.a == relationalStudiableItem.a && this.b == relationalStudiableItem.b && this.c == relationalStudiableItem.c && this.d == relationalStudiableItem.d && this.e == relationalStudiableItem.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + d0.d(d0.d((this.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelationalStudiableItem(id=");
        sb.append(this.a);
        sb.append(", type=");
        sb.append(this.b);
        sb.append(", studiableContainerId=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", lastModified=");
        return a.g(this.e, ")", sb);
    }
}
