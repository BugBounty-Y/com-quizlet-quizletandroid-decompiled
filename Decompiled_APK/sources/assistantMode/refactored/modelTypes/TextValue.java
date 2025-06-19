package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
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
public final class TextValue implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, null, null, null, new kotlinx.serialization.a(K.a(String.class), R1.e(q0.a), new KSerializer[0])};
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TextValue$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TextValue(int i, String str, String str2, String str3, String str4, String str5) {
        if (15 != (i & 15)) {
            AbstractC5047c0.k(i, 15, TextValue$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = str4;
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = str5;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TextValue)) {
            return false;
        }
        TextValue textValue = (TextValue) obj;
        return Intrinsics.b(this.a, textValue.a) && Intrinsics.b(this.b, textValue.b) && Intrinsics.b(this.c, textValue.c) && Intrinsics.b(this.d, textValue.d) && Intrinsics.b(this.e, textValue.e);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.e;
        return iHashCode2 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextValue(plainText=");
        sb.append(this.a);
        sb.append(", languageCode=");
        sb.append(this.b);
        sb.append(", ttsUrl=");
        sb.append(this.c);
        sb.append(", ttsSlowUrl=");
        sb.append(this.d);
        sb.append(", richText=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }

    public TextValue(String plainText, String languageCode, String str, String str2, String str3) {
        Intrinsics.checkNotNullParameter(plainText, "plainText");
        Intrinsics.checkNotNullParameter(languageCode, "languageCode");
        this.a = plainText;
        this.b = languageCode;
        this.c = str;
        this.d = str2;
        this.e = str3;
    }
}
