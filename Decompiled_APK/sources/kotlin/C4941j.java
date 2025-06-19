package kotlin;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: kotlin.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4941j implements Comparable {

    @NotNull
    public static final C4940i b = new C4940i(null);
    public static final C4941j c = new C4941j();
    public final int a = 131093;

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        C4941j other = (C4941j) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        return this.a - other.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        C4941j c4941j = obj instanceof C4941j ? (C4941j) obj : null;
        return c4941j != null && this.a == c4941j.a;
    }

    public final int hashCode() {
        return this.a;
    }

    public final String toString() {
        return "2.0.21";
    }
}
