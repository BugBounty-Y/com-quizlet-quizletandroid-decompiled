package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class ImageValue implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final int b;
    public final int c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ImageValue$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ImageValue(int i, int i2, String str, int i3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, ImageValue$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = i2;
        this.c = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ImageValue)) {
            return false;
        }
        ImageValue imageValue = (ImageValue) obj;
        return Intrinsics.b(this.a, imageValue.a) && this.b == imageValue.b && this.c == imageValue.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ImageValue(url=");
        sb.append(this.a);
        sb.append(", width=");
        sb.append(this.b);
        sb.append(", height=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }

    public ImageValue(String url, int i, int i2) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = url;
        this.b = i;
        this.c = i2;
    }
}
