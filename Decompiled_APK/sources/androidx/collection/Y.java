package androidx.collection;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.collections.AbstractC4916g;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.internal.C5070y;

/* loaded from: classes.dex */
public class Y implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public int b;
    public final Object c;

    public /* synthetic */ Y(Object obj, int i) {
        this.a = i;
        this.c = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.b < ((W) this.c).g()) {
                }
                break;
            case 1:
                if (this.b < ((byte[]) this.c).length) {
                }
                break;
            case 2:
                if (this.b < ((int[]) this.c).length) {
                }
                break;
            case 3:
                if (this.b < ((long[]) this.c).length) {
                }
                break;
            case 4:
                if (this.b < ((short[]) this.c).length) {
                }
                break;
            case 5:
                if (this.b < ((AbstractC4916g) this.c).a()) {
                }
                break;
            case 6:
                if (this.b < ((Object[]) this.c).length) {
                }
                break;
            default:
                if (this.b > 0) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                int i = this.b;
                this.b = i + 1;
                return ((W) this.c).h(i);
            case 1:
                int i2 = this.b;
                byte[] bArr = (byte[]) this.c;
                if (i2 >= bArr.length) {
                    throw new NoSuchElementException(String.valueOf(this.b));
                }
                this.b = i2 + 1;
                return new kotlin.x(bArr[i2]);
            case 2:
                int i3 = this.b;
                int[] iArr = (int[]) this.c;
                if (i3 >= iArr.length) {
                    throw new NoSuchElementException(String.valueOf(this.b));
                }
                this.b = i3 + 1;
                return new kotlin.A(iArr[i3]);
            case 3:
                int i4 = this.b;
                long[] jArr = (long[]) this.c;
                if (i4 >= jArr.length) {
                    throw new NoSuchElementException(String.valueOf(this.b));
                }
                this.b = i4 + 1;
                return new kotlin.D(jArr[i4]);
            case 4:
                int i5 = this.b;
                short[] sArr = (short[]) this.c;
                if (i5 >= sArr.length) {
                    throw new NoSuchElementException(String.valueOf(this.b));
                }
                this.b = i5 + 1;
                return new kotlin.H(sArr[i5]);
            case 5:
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                int i6 = this.b;
                this.b = i6 + 1;
                return ((AbstractC4916g) this.c).get(i6);
            case 6:
                try {
                    Object[] objArr = (Object[]) this.c;
                    int i7 = this.b;
                    this.b = i7 + 1;
                    return objArr[i7];
                } catch (ArrayIndexOutOfBoundsException e) {
                    this.b--;
                    throw new NoSuchElementException(e.getMessage());
                }
            default:
                C5070y c5070y = (C5070y) this.c;
                int i8 = this.b;
                this.b = i8 - 1;
                return c5070y.e[c5070y.c - i8];
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 2:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 3:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 4:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 5:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 6:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public Y(Object[] array) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(array, "array");
        this.c = array;
    }

    public Y(byte[] array) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(array, "array");
        this.c = array;
    }

    public Y(int[] array) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(array, "array");
        this.c = array;
    }

    public Y(long[] array) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(array, "array");
        this.c = array;
    }

    public Y(short[] array) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(array, "array");
        this.c = array;
    }

    public Y(C5070y c5070y) {
        this.a = 7;
        this.c = c5070y;
        this.b = c5070y.c;
    }
}
