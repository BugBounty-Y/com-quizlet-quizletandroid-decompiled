package kotlinx.collections.immutable.implementations.immutableList;

import com.google.android.gms.internal.mlkit_vision_camera.A1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3413y1;
import java.util.ListIterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends a {
    public final Object[] b;
    public final Object[] c;
    public final int d;
    public final int e;

    public c(Object[] root, Object[] tail, int i, int i2) {
        Intrinsics.checkNotNullParameter(root, "root");
        Intrinsics.checkNotNullParameter(tail, "tail");
        this.b = root;
        this.c = tail;
        this.d = i;
        this.e = i2;
        if (a() > 32) {
            int length = tail.length;
        } else {
            throw new IllegalArgumentException(("Trie-based persistent vector should have at least 33 elements, got " + a()).toString());
        }
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.d;
    }

    @Override // java.util.List
    public final Object get(int i) {
        Object[] objArr;
        int i2 = this.d;
        A1.e(i, i2);
        if (((i2 - 1) & (-32)) <= i) {
            objArr = this.c;
        } else {
            objArr = this.b;
            for (int i3 = this.e; i3 > 0; i3 -= 5) {
                Object obj = objArr[AbstractC3413y1.b(i, i3)];
                Intrinsics.e(obj, "null cannot be cast to non-null type kotlin.Array<kotlin.Any?>");
                objArr = (Object[]) obj;
            }
        }
        return objArr[i & 31];
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final ListIterator listIterator(int i) {
        A1.f(i, this.d);
        return new e(this.b, i, this.c, this.d, (this.e / 5) + 1);
    }
}
