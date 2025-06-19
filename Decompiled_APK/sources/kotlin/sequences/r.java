package kotlin.sequences;

import androidx.collection.L;
import androidx.compose.animation.d0;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements Sequence, c {
    public final Sequence a;
    public final int b;
    public final int c;

    public r(Sequence sequence, int i, int i2) {
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        this.a = sequence;
        this.b = i;
        this.c = i2;
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "startIndex should be non-negative, but is ").toString());
        }
        if (i2 < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "endIndex should be non-negative, but is ").toString());
        }
        if (i2 < i) {
            throw new IllegalArgumentException(d0.p("endIndex should be not less than startIndex, but was ", i2, " < ", i).toString());
        }
    }

    @Override // kotlin.sequences.c
    public final Sequence a(int i) {
        int i2 = this.c;
        int i3 = this.b;
        if (i >= i2 - i3) {
            return d.a;
        }
        return new r(this.a, i3 + i, i2);
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return new L(this);
    }

    @Override // kotlin.sequences.c
    public final Sequence take() {
        int i = this.c;
        int i2 = this.b;
        if (7 >= i - i2) {
            return this;
        }
        return new r(this.a, i2, i2 + 7);
    }
}
