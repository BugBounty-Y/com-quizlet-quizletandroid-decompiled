package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AdsState {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;
    public final boolean b;
    public final boolean c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AdsState$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AdsState(int i, boolean z, boolean z2, boolean z3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, AdsState$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AdsState)) {
            return false;
        }
        AdsState adsState = (AdsState) obj;
        return this.a == adsState.a && this.b == adsState.b && this.c == adsState.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AdsState(shouldShowAds=");
        sb.append(this.a);
        sb.append(", shouldPreloadAds=");
        sb.append(this.b);
        sb.append(", hasExceedsMaxNumAdsShown=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
