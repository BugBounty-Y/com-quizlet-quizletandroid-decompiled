package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.enums.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class VideoValue implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final G b;
    public final int c;
    public final int d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return VideoValue$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ VideoValue(int i, String str, G g, int i2, int i3) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, VideoValue$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = g;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof VideoValue)) {
            return false;
        }
        VideoValue videoValue = (VideoValue) obj;
        return Intrinsics.b(this.a, videoValue.a) && this.b == videoValue.b && this.c == videoValue.c && this.d == videoValue.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31);
    }

    public final String toString() {
        return "VideoValue(providerVideoId=" + this.a + ", provider=" + this.b + ", clipStartSeconds=" + this.c + ", clipEndSeconds=" + this.d + ")";
    }
}
