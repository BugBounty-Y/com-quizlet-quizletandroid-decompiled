package kotlinx.collections.immutable.implementations.immutableList;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3413y1;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.a {
    public int d;
    public Object[] e;
    public boolean f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r5v1 */
    /* JADX WARN: Type inference failed for: r5v2, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r5v3 */
    public h(Object[] root, int i, int i2, int i3) {
        super(i, i2, 1);
        Intrinsics.checkNotNullParameter(root, "root");
        this.d = i3;
        Object[] objArr = new Object[i3];
        this.e = objArr;
        ?? r5 = i == i2 ? 1 : 0;
        this.f = r5;
        objArr[0] = root;
        b(i - r5, 1);
    }

    public final Object a() {
        int i = this.b & 31;
        Object obj = this.e[this.d - 1];
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<E of kotlinx.collections.immutable.implementations.immutableList.TrieIterator>");
        return ((Object[]) obj)[i];
    }

    public final void b(int i, int i2) {
        int i3 = (this.d - i2) * 5;
        while (i2 < this.d) {
            Object[] objArr = this.e;
            Object obj = objArr[i2 - 1];
            Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
            objArr[i2] = ((Object[]) obj)[AbstractC3413y1.b(i, i3)];
            i3 -= 5;
            i2++;
        }
    }

    public final void d(int i) {
        int i2 = 0;
        while (AbstractC3413y1.b(this.b, i2) == i) {
            i2 += 5;
        }
        if (i2 > 0) {
            b(this.b, ((this.d - 1) - (i2 / 5)) + 1);
        }
    }

    @Override // java.util.ListIterator, java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        Object objA = a();
        int i = this.b + 1;
        this.b = i;
        if (i == this.c) {
            this.f = true;
            return objA;
        }
        d(0);
        return objA;
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        this.b--;
        if (this.f) {
            this.f = false;
            return a();
        }
        d(31);
        return a();
    }
}
