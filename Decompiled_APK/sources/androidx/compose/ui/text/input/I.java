package androidx.compose.ui.text.input;

import androidx.compose.ui.text.C0995g;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I {
    public final C0995g a;
    public final s b;

    public I(C0995g c0995g, s sVar) {
        this.a = c0995g;
        this.b = sVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        return Intrinsics.b(this.a, i.a) && Intrinsics.b(this.b, i.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TransformedText(text=" + ((Object) this.a) + ", offsetMapping=" + this.b + ')';
    }
}
