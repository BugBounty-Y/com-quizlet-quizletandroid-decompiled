package assistantMode.types.unions;

import androidx.compose.animation.d0;
import assistantMode.enums.G;
import assistantMode.refactored.enums.h;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class VideoAttribute implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final G b;
    public final int c;
    public final int d;
    public final h e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return VideoAttribute$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ VideoAttribute(int i, String str, G g, int i2, int i3, h hVar) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, VideoAttribute$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = g;
        this.c = i2;
        this.d = i3;
        if ((i & 16) == 0) {
            this.e = h.d;
        } else {
            this.e = hVar;
        }
    }

    @Override // assistantMode.types.unions.a
    public final h a() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof VideoAttribute)) {
            return false;
        }
        VideoAttribute videoAttribute = (VideoAttribute) obj;
        return Intrinsics.b(this.a, videoAttribute.a) && this.b == videoAttribute.b && this.c == videoAttribute.c && this.d == videoAttribute.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, (this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31);
    }

    public final String toString() {
        return "VideoAttribute(providerVideoId=" + this.a + ", provider=" + this.b + ", clipStartSeconds=" + this.c + ", clipEndSeconds=" + this.d + ")";
    }

    public VideoAttribute(String providerVideoId, G provider, int i, int i2) {
        Intrinsics.checkNotNullParameter(providerVideoId, "providerVideoId");
        Intrinsics.checkNotNullParameter(provider, "provider");
        this.a = providerVideoId;
        this.b = provider;
        this.c = i;
        this.d = i2;
        this.e = h.d;
    }
}
