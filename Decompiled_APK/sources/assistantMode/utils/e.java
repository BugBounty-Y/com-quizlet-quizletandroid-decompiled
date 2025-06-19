package assistantMode.utils;

import com.google.android.gms.internal.mlkit_vision_camera.k3;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final k3 a;
    public final k3 b;

    public e(k3 wordText, k3 definitionText) {
        Intrinsics.checkNotNullParameter(wordText, "wordText");
        Intrinsics.checkNotNullParameter(definitionText, "definitionText");
        this.a = wordText;
        this.b = definitionText;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Texts(wordText=" + this.a + ", definitionText=" + this.b + ")";
    }
}
