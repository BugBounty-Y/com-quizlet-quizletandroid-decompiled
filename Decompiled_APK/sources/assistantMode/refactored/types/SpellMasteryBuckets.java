package assistantMode.refactored.types;

import androidx.compose.animation.d0;
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
public final class SpellMasteryBuckets implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d;
    public final List a;
    public final List b;
    public final List c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return SpellMasteryBuckets$$serializer.INSTANCE;
        }
    }

    static {
        P p = P.a;
        d = new KSerializer[]{new C5048d(p, 0), new C5048d(p, 0), new C5048d(p, 0)};
    }

    public /* synthetic */ SpellMasteryBuckets(int i, List list, List list2, List list3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, SpellMasteryBuckets$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = list3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SpellMasteryBuckets)) {
            return false;
        }
        SpellMasteryBuckets spellMasteryBuckets = (SpellMasteryBuckets) obj;
        return Intrinsics.b(this.a, spellMasteryBuckets.a) && Intrinsics.b(this.b, spellMasteryBuckets.b) && Intrinsics.b(this.c, spellMasteryBuckets.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SpellMasteryBuckets(correctZeroTimes=");
        sb.append(this.a);
        sb.append(", correctOneTime=");
        sb.append(this.b);
        sb.append(", correctTwoTimes=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public SpellMasteryBuckets(ArrayList correctZeroTimes, ArrayList correctOneTime, ArrayList correctTwoTimes) {
        Intrinsics.checkNotNullParameter(correctZeroTimes, "correctZeroTimes");
        Intrinsics.checkNotNullParameter(correctOneTime, "correctOneTime");
        Intrinsics.checkNotNullParameter(correctTwoTimes, "correctTwoTimes");
        this.a = correctZeroTimes;
        this.b = correctOneTime;
        this.c = correctTwoTimes;
    }
}
