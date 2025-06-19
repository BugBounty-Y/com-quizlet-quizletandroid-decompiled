package assistantMode.types.unions;

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
public final class AudioAttribute implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final h c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AudioAttribute$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AudioAttribute(int i, String str, String str2, h hVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, AudioAttribute$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        if ((i & 4) == 0) {
            this.c = h.e;
        } else {
            this.c = hVar;
        }
    }

    @Override // assistantMode.types.unions.a
    public final h a() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AudioAttribute)) {
            return false;
        }
        AudioAttribute audioAttribute = (AudioAttribute) obj;
        return Intrinsics.b(this.a, audioAttribute.a) && Intrinsics.b(this.b, audioAttribute.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AudioAttribute(url=");
        sb.append(this.a);
        sb.append(", slowUrl=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }

    public AudioAttribute(String url, String slowUrl) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(slowUrl, "slowUrl");
        this.a = url;
        this.b = slowUrl;
        this.c = h.e;
    }
}
