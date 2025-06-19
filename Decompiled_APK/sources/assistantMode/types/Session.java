package assistantMode.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class Session {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final long g;
    public final long h;
    public final boolean i;
    public final boolean j;
    public final long k;
    public final Long l;
    public final Long m;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Session$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Session(int i, long j, long j2, long j3, long j4, long j5, long j6, long j7, long j8, boolean z, boolean z2, long j9, Long l, Long l2) {
        if (8191 != (i & 8191)) {
            AbstractC5047c0.k(i, 8191, Session$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
        this.f = j6;
        this.g = j7;
        this.h = j8;
        this.i = z;
        this.j = z2;
        this.k = j9;
        this.l = l;
        this.m = l2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Session)) {
            return false;
        }
        Session session = (Session) obj;
        return this.a == session.a && this.b == session.b && this.c == session.c && this.d == session.d && this.e == session.e && this.f == session.f && this.g == session.g && this.h == session.h && this.i == session.i && this.j == session.j && this.k == session.k && Intrinsics.b(this.l, session.l) && Intrinsics.b(this.m, session.m);
    }

    public final int hashCode() {
        int iD = d0.d(d0.g(d0.g(d0.d(d0.d(d0.d(d0.d(d0.d(d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j), 31, this.k);
        Long l = this.l;
        int iHashCode = (iD + (l == null ? 0 : l.hashCode())) * 31;
        Long l2 = this.m;
        return iHashCode + (l2 != null ? l2.hashCode() : 0);
    }

    public final String toString() {
        return "Session(id=" + this.a + ", personId=" + this.b + ", itemId=" + this.c + ", itemType=" + this.d + ", timestamp=" + this.e + ", endedTimestamp=" + this.f + ", type=" + this.g + ", score=" + this.h + ", hidden=" + this.i + ", selectedOnly=" + this.j + ", lastModified=" + this.k + ", _folderId=" + this.l + ", _setId=" + this.m + ")";
    }
}
