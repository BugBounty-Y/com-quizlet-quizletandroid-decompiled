package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AdsSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public final int a;
    public final int b;
    public final Integer c;
    public final Integer d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AdsSettings$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AdsSettings(int i, int i2, int i3, Integer num, Integer num2) {
        if (1 != (i & 1)) {
            AbstractC5047c0.k(i, 1, AdsSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = i2;
        if ((i & 2) == 0) {
            this.b = 2;
        } else {
            this.b = i3;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = num;
        }
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = num2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AdsSettings)) {
            return false;
        }
        AdsSettings adsSettings = (AdsSettings) obj;
        return this.a == adsSettings.a && this.b == adsSettings.b && Intrinsics.b(this.c, adsSettings.c) && Intrinsics.b(this.d, adsSettings.d);
    }

    public final int hashCode() {
        int iB = d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
        Integer num = this.c;
        int iHashCode = (iB + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.d;
        return iHashCode + (num2 != null ? num2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AdsSettings(numCardsToShowAds=");
        sb.append(this.a);
        sb.append(", numCardsPriorToPreloadAds=");
        sb.append(this.b);
        sb.append(", minShownInterval=");
        sb.append(this.c);
        sb.append(", maxNumAds=");
        return assistantMode.refactored.a.l(sb, this.d, ")");
    }
}
