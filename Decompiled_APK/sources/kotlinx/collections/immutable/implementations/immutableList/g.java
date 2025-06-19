package kotlinx.collections.immutable.implementations.immutableList;

import com.google.android.gms.internal.mlkit_vision_camera.A1;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.ListIterator;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends a implements kotlinx.collections.immutable.b {
    public static final g c = new g(new Object[0]);
    public final Object[] b;

    public g(Object[] buffer) {
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        this.b = buffer;
        int length = buffer.length;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.length;
    }

    public final kotlinx.collections.immutable.e b(Collection elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        if (elements.isEmpty()) {
            return this;
        }
        Object[] objArr = this.b;
        if (elements.size() + objArr.length > 32) {
            d dVarE = e();
            dVarE.addAll(elements);
            return dVarE.e();
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, elements.size() + objArr.length);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        int length = objArr.length;
        Iterator it2 = elements.iterator();
        while (it2.hasNext()) {
            objArrCopyOf[length] = it2.next();
            length++;
        }
        return new g(objArrCopyOf);
    }

    public final d e() {
        return new d(this, null, this.b, 0);
    }

    @Override // java.util.List
    public final Object get(int i) {
        A1.e(i, a());
        return this.b[i];
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int indexOf(Object obj) {
        return C4933y.G(obj, this.b);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final int lastIndexOf(Object obj) {
        return C4933y.I(obj, this.b);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List
    public final ListIterator listIterator(int i) {
        Object[] objArr = this.b;
        A1.f(i, objArr.length);
        return new b(objArr, i, objArr.length);
    }
}
