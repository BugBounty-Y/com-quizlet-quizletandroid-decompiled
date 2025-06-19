package assistantMode.types.unions;

import androidx.compose.animation.d0;
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
public final class ImageAttribute implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final int b;
    public final int c;
    public final h d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ImageAttribute$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ImageAttribute(int i, String str, int i2, int i3, h hVar) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, ImageAttribute$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = i2;
        this.c = i3;
        if ((i & 8) == 0) {
            this.d = h.c;
        } else {
            this.d = hVar;
        }
    }

    @Override // assistantMode.types.unions.a
    public final h a() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ImageAttribute)) {
            return false;
        }
        ImageAttribute imageAttribute = (ImageAttribute) obj;
        return Intrinsics.b(this.a, imageAttribute.a) && this.b == imageAttribute.b && this.c == imageAttribute.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ImageAttribute(url=");
        sb.append(this.a);
        sb.append(", width=");
        sb.append(this.b);
        sb.append(", height=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }

    public ImageAttribute(String url, int i, int i2) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = url;
        this.b = i;
        this.c = i2;
        this.d = h.c;
    }
}
