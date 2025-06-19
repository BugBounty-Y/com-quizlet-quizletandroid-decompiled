package assistantMode.refactored.types;

import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AndroidWriteMasteryBuckets implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c;
    public final List a;
    public final List b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AndroidWriteMasteryBuckets$$serializer.INSTANCE;
        }
    }

    static {
        P p = P.a;
        c = new KSerializer[]{new C5048d(p, 0), new C5048d(p, 0)};
    }

    public /* synthetic */ AndroidWriteMasteryBuckets(int i, List list, List list2) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, AndroidWriteMasteryBuckets$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AndroidWriteMasteryBuckets)) {
            return false;
        }
        AndroidWriteMasteryBuckets androidWriteMasteryBuckets = (AndroidWriteMasteryBuckets) obj;
        return Intrinsics.b(this.a, androidWriteMasteryBuckets.a) && Intrinsics.b(this.b, androidWriteMasteryBuckets.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AndroidWriteMasteryBuckets(correctZeroTimes=" + this.a + ", correctOneTime=" + this.b + ")";
    }

    public AndroidWriteMasteryBuckets(ArrayList correctZeroTimes, ArrayList correctOneTime) {
        Intrinsics.checkNotNullParameter(correctZeroTimes, "correctZeroTimes");
        Intrinsics.checkNotNullParameter(correctOneTime, "correctOneTime");
        this.a = correctZeroTimes;
        this.b = correctOneTime;
    }
}
