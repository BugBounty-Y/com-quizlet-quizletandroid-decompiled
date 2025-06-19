package kotlin.ranges;

import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class IntRange extends h {

    @NotNull
    public static final j e = new j(null);
    public static final IntRange f = new IntRange(1, 0, 1);

    public final boolean b(int i) {
        return this.a <= i && i <= this.b;
    }

    @Override // kotlin.ranges.h
    public final boolean equals(Object obj) {
        if (!(obj instanceof IntRange)) {
            return false;
        }
        if (isEmpty() && ((IntRange) obj).isEmpty()) {
            return true;
        }
        IntRange intRange = (IntRange) obj;
        if (this.a == intRange.a) {
            return this.b == intRange.b;
        }
        return false;
    }

    @Override // kotlin.ranges.h
    public final int hashCode() {
        if (isEmpty()) {
            return -1;
        }
        return (this.a * 31) + this.b;
    }

    @Override // kotlin.ranges.h
    public final boolean isEmpty() {
        return this.a > this.b;
    }

    @Override // kotlin.ranges.h
    public final String toString() {
        return this.a + ".." + this.b;
    }
}
