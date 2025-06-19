package assistantMode.refactored.modelTypes.relational;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.h;
import assistantMode.refactored.enums.n;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.refactored.modelTypes.TextValue;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class RelationalStudiableMediaConnection {

    @NotNull
    public static final Companion Companion = new Companion();
    public final n a;
    public final long b;
    public final h c;
    public final TextValue d;
    public final AudioValue e;
    public final ImageValue f;
    public final DiagramShapeValue g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RelationalStudiableMediaConnection$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RelationalStudiableMediaConnection(int i, n nVar, long j, h hVar, TextValue textValue, AudioValue audioValue, ImageValue imageValue, DiagramShapeValue diagramShapeValue) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, RelationalStudiableMediaConnection$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = nVar;
        this.b = j;
        this.c = hVar;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = textValue;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = audioValue;
        }
        if ((i & 32) == 0) {
            this.f = null;
        } else {
            this.f = imageValue;
        }
        if ((i & 64) == 0) {
            this.g = null;
        } else {
            this.g = diagramShapeValue;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RelationalStudiableMediaConnection)) {
            return false;
        }
        RelationalStudiableMediaConnection relationalStudiableMediaConnection = (RelationalStudiableMediaConnection) obj;
        return this.a == relationalStudiableMediaConnection.a && this.b == relationalStudiableMediaConnection.b && this.c == relationalStudiableMediaConnection.c && Intrinsics.b(this.d, relationalStudiableMediaConnection.d) && Intrinsics.b(this.e, relationalStudiableMediaConnection.e) && Intrinsics.b(this.f, relationalStudiableMediaConnection.f) && Intrinsics.b(this.g, relationalStudiableMediaConnection.g);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + d0.d(this.a.hashCode() * 31, 31, this.b)) * 31;
        TextValue textValue = this.d;
        int iHashCode2 = (iHashCode + (textValue == null ? 0 : textValue.hashCode())) * 31;
        AudioValue audioValue = this.e;
        int iHashCode3 = (iHashCode2 + (audioValue == null ? 0 : audioValue.a.hashCode())) * 31;
        ImageValue imageValue = this.f;
        int iHashCode4 = (iHashCode3 + (imageValue == null ? 0 : imageValue.hashCode())) * 31;
        DiagramShapeValue diagramShapeValue = this.g;
        return iHashCode4 + (diagramShapeValue != null ? diagramShapeValue.a.hashCode() : 0);
    }

    public final String toString() {
        return "RelationalStudiableMediaConnection(connectionType=" + this.a + ", connectionModelId=" + this.b + ", mediaType=" + this.c + ", text=" + this.d + ", audio=" + this.e + ", image=" + this.f + ", diagramShape=" + this.g + ")";
    }
}
