package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.EnumC1450d;
import assistantMode.types.CheckpointMetadata;
import assistantMode.types.F;
import assistantMode.types.RoundResultItem$$serializer;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class Checkpoint implements e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, null, new C5048d(RoundResultItem$$serializer.INSTANCE, 0), null, null};
    public final EnumC1450d a;
    public final boolean b;
    public final List c;
    public final Integer d;
    public final CheckpointMetadata e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Checkpoint$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Checkpoint(int i, EnumC1450d enumC1450d, boolean z, List list, Integer num, CheckpointMetadata checkpointMetadata) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, Checkpoint$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = enumC1450d;
        this.b = z;
        this.c = list;
        this.d = num;
        if ((i & 16) == 0) {
            this.e = new CheckpointMetadata();
        } else {
            this.e = checkpointMetadata;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Checkpoint)) {
            return false;
        }
        Checkpoint checkpoint = (Checkpoint) obj;
        return this.a == checkpoint.a && this.b == checkpoint.b && Intrinsics.b(this.c, checkpoint.c) && Intrinsics.b(this.d, checkpoint.d) && Intrinsics.b(this.e, checkpoint.e);
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.e;
    }

    public final int hashCode() {
        int iG = d0.g(this.a.hashCode() * 31, 31, this.b);
        List list = this.c;
        int iHashCode = (iG + (list == null ? 0 : list.hashCode())) * 31;
        Integer num = this.d;
        return this.e.hashCode() + ((iHashCode + (num != null ? num.hashCode() : 0)) * 31);
    }

    public final String toString() {
        return "Checkpoint(progressState=" + this.a + ", hasCompletedStudying=" + this.b + ", roundResults=" + this.c + ", checkpointNumber=" + this.d + ", metadata=" + this.e + ")";
    }

    public Checkpoint(EnumC1450d progressState, boolean z, ArrayList arrayList, Integer num) {
        CheckpointMetadata metadata = new CheckpointMetadata();
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = progressState;
        this.b = z;
        this.c = arrayList;
        this.d = num;
        this.e = metadata;
    }
}
