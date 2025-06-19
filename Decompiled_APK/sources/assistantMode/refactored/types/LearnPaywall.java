package assistantMode.refactored.types;

import assistantMode.types.F;
import assistantMode.types.PaywallMetadata;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class LearnPaywall implements g {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Checkpoint a;
    public final PaywallMetadata b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return LearnPaywall$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ LearnPaywall(int i, Checkpoint checkpoint, PaywallMetadata paywallMetadata) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, LearnPaywall$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = checkpoint;
        if ((i & 2) == 0) {
            this.b = new PaywallMetadata();
        } else {
            this.b = paywallMetadata;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LearnPaywall)) {
            return false;
        }
        LearnPaywall learnPaywall = (LearnPaywall) obj;
        return Intrinsics.b(this.a, learnPaywall.a) && Intrinsics.b(this.b, learnPaywall.b);
    }

    @Override // assistantMode.refactored.types.g
    public final F getMetadata() {
        return this.b;
    }

    public final int hashCode() {
        Checkpoint checkpoint = this.a;
        return this.b.hashCode() + ((checkpoint == null ? 0 : checkpoint.hashCode()) * 31);
    }

    public final String toString() {
        return "LearnPaywall(checkpoint=" + this.a + ", metadata=" + this.b + ")";
    }

    public LearnPaywall(Checkpoint checkpoint, PaywallMetadata metadata) {
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = checkpoint;
        this.b = metadata;
    }
}
