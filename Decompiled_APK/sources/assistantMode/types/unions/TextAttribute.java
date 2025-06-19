package assistantMode.types.unions;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.h;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class TextAttribute implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {null, null, new kotlinx.serialization.a(K.a(String.class), R1.e(q0.a), new KSerializer[0]), null};
    public final String a;
    public final String b;
    public final String c;
    public final h d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TextAttribute$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TextAttribute(int i, String str, String str2, String str3, h hVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, TextAttribute$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = str3;
        }
        if ((i & 8) == 0) {
            this.d = h.b;
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
        if (!(obj instanceof TextAttribute)) {
            return false;
        }
        TextAttribute textAttribute = (TextAttribute) obj;
        return Intrinsics.b(this.a, textAttribute.a) && Intrinsics.b(this.b, textAttribute.b) && Intrinsics.b(this.c, textAttribute.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextAttribute(plainText=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", richText=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    public TextAttribute(String plainText, String languageCode, String str) {
        Intrinsics.checkNotNullParameter(plainText, "plainText");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = plainText;
        this.b = languageCode;
        this.c = str;
        this.d = h.b;
    }
}
