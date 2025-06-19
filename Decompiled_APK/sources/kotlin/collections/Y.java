package kotlin.collections;

import java.util.Arrays;
import java.util.Iterator;
import java.util.RandomAccess;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Y extends AbstractC4916g implements RandomAccess {
    public final Object[] b;
    public final int c;
    public int d;
    public int e;

    public Y(Object[] buffer, int i) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.b = buffer;
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "ring buffer filled size should not be negative but it is ").toString());
        }
        if (i <= buffer.length) {
            this.c = buffer.length;
            this.e = i;
        } else {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "ring buffer filled size: ", " cannot be larger than the buffer size: ");
            sbV.append(buffer.length);
            throw new IllegalArgumentException(sbV.toString().toString());
        }
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.e;
    }

    public final void b(int i) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "n shouldn't be negative but it is ").toString());
        }
        if (i > this.e) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i, "n shouldn't be greater than the buffer size: n = ", ", size = ");
            sbV.append(this.e);
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        if (i > 0) {
            int i2 = this.d;
            int i3 = this.c;
            int i4 = (i2 + i) % i3;
            Object[] objArr = this.b;
            if (i2 > i4) {
                C4930v.o(objArr, null, i2, i3);
                Intrinsics.checkNotNullParameter(objArr, "<this>");
                Arrays.fill(objArr, 0, i4, (Object) null);
            } else {
                C4930v.o(objArr, null, i2, i4);
            }
            this.d = i4;
            this.e -= i;
        }
    }

    @Override // java.util.List
    public final Object get(int i) {
        C4913d c4913d = AbstractC4916g.a;
        int i2 = this.e;
        c4913d.getClass();
        C4913d.b(i, i2);
        return this.b[(this.d + i) % this.c];
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.Collection, java.lang.Iterable, java.util.List
    public final Iterator iterator() {
        return new X(this);
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final Object[] toArray() {
        return toArray(new Object[a()]);
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final Object[] toArray(Object[] array) {
        Object[] objArr;
        Intrinsics.checkNotNullParameter(array, "array");
        int length = array.length;
        int i = this.e;
        if (length < i) {
            array = Arrays.copyOf(array, i);
            Intrinsics.checkNotNullExpressionValue(array, "copyOf(...)");
        }
        int i2 = this.e;
        int i3 = this.d;
        int i4 = 0;
        int i5 = 0;
        while (true) {
            objArr = this.b;
            if (i5 >= i2 || i3 >= this.c) {
                break;
            }
            array[i5] = objArr[i3];
            i5++;
            i3++;
        }
        while (i5 < i2) {
            array[i5] = objArr[i4];
            i5++;
            i4++;
        }
        A.e(i2, array);
        return array;
    }
}
