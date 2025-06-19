package assistantMode.refactored.modelTypes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class AudioValue implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AudioValue$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AudioValue(int i, String str) {
        if (1 == (i & 1)) {
            this.a = str;
        } else {
            AbstractC5047c0.k(i, 1, AudioValue$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof AudioValue) && Intrinsics.b(this.a, ((AudioValue) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("AudioValue(url="), this.a, ")");
    }

    public AudioValue(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = url;
    }
}
