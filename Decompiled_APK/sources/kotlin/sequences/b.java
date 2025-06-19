package kotlin.sequences;

import androidx.compose.animation.d0;
import java.util.Iterator;
import kotlin.collections.O;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements Sequence, c {
    public final Sequence a;
    public final int b;

    public b(Sequence sequence, int i) {
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        this.a = sequence;
        this.b = i;
        if (i < 0) {
            throw new IllegalArgumentException(d0.m('.', i, "count must be non-negative, but was ").toString());
        }
    }

    @Override // kotlin.sequences.c
    public final Sequence a(int i) {
        int i2 = this.b + i;
        return i2 < 0 ? new b(this, i) : new b(this.a, i2);
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        return new O(this);
    }

    @Override // kotlin.sequences.c
    public final Sequence take() {
        int i = this.b;
        int i2 = i + 7;
        return i2 < 0 ? new s(this) : new r(this.a, i, i2);
    }
}
