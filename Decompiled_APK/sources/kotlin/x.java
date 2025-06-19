package kotlin;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class x implements Comparable {

    @NotNull
    public static final w b = new w(null);
    public final byte a;

    public /* synthetic */ x(byte b2) {
        this.a = b2;
    }

    @Override // java.lang.Comparable
    public final /* synthetic */ int compareTo(Object obj) {
        return Intrinsics.g(this.a & 255, ((x) obj).a & 255);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof x) {
            return this.a == ((x) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Byte.hashCode(this.a);
    }

    public final String toString() {
        return String.valueOf(this.a & 255);
    }
}
