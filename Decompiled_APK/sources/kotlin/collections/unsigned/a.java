package kotlin.collections.unsigned;

import java.util.RandomAccess;
import kotlin.D;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends AbstractC4916g implements RandomAccess {
    public final /* synthetic */ long[] b;

    public a(long[] jArr) {
        this.b = jArr;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.length;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        if (!(obj instanceof D)) {
            return false;
        }
        return C4933y.x(this.b, ((D) obj).a);
    }

    @Override // java.util.List
    public final Object get(int i) {
        return new D(this.b[i]);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int indexOf(Object obj) {
        if (!(obj instanceof D)) {
            return -1;
        }
        long j = ((D) obj).a;
        long[] jArr = this.b;
        Intrinsics.checkNotNullParameter(jArr, "<this>");
        int length = jArr.length;
        for (int i = 0; i < length; i++) {
            if (j == jArr[i]) {
                return i;
            }
        }
        return -1;
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection
    public final boolean isEmpty() {
        return this.b.length == 0;
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int lastIndexOf(Object obj) {
        if (!(obj instanceof D)) {
            return -1;
        }
        long j = ((D) obj).a;
        long[] jArr = this.b;
        Intrinsics.checkNotNullParameter(jArr, "<this>");
        int length = jArr.length - 1;
        if (length >= 0) {
            while (true) {
                int i = length - 1;
                if (j == jArr[length]) {
                    return length;
                }
                if (i < 0) {
                    break;
                }
                length = i;
            }
        }
        return -1;
    }
}
