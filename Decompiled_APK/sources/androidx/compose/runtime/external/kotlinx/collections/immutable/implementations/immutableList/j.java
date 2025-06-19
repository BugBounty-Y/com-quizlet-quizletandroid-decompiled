package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import com.google.android.gms.internal.mlkit_vision_barcode.I4;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.ListIterator;
import kotlin.collections.C4930v;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j extends c {
    public static final j c = new j(new Object[0]);
    public final Object[] b;

    public j(Object[] objArr) {
        this.b = objArr;
        int length = objArr.length;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c Y(b bVar) {
        Object[] objArr = this.b;
        int length = objArr.length;
        int length2 = objArr.length;
        Object[] objArrCopyOf = objArr;
        boolean z = false;
        for (int i = 0; i < length2; i++) {
            Object obj = objArr[i];
            if (((Boolean) bVar.invoke(obj)).booleanValue()) {
                if (!z) {
                    objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
                    Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
                    z = true;
                    length = i;
                }
            } else if (z) {
                objArrCopyOf[length] = obj;
                length++;
            }
        }
        return length == objArr.length ? this : length == 0 ? c : new j(C4930v.n(0, length, objArrCopyOf));
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        return this.b.length;
    }

    @Override // java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c add(int i, Object obj) {
        Object[] objArr = this.b;
        I4.c(i, objArr.length);
        if (i == objArr.length) {
            return add(obj);
        }
        if (objArr.length < 32) {
            Object[] objArr2 = new Object[objArr.length + 1];
            C4930v.j(objArr, 0, objArr2, i, 6);
            C4930v.h(objArr, i + 1, objArr2, i, objArr.length);
            objArr2[i] = obj;
            return new j(objArr2);
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        C4930v.h(objArr, i + 1, objArrCopyOf, i, objArr.length - 1);
        objArrCopyOf[i] = obj;
        Object[] objArr3 = new Object[32];
        objArr3[0] = objArr[31];
        return new f(objArrCopyOf, objArr3, objArr.length + 1, 0);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.c, java.util.Collection, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c addAll(Collection collection) {
        Object[] objArr = this.b;
        if (collection.size() + objArr.length > 32) {
            g gVarBuilder = builder();
            gVarBuilder.addAll(collection);
            return gVarBuilder.e();
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, collection.size() + objArr.length);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        int length = objArr.length;
        Iterator it2 = collection.iterator();
        while (it2.hasNext()) {
            objArrCopyOf[length] = it2.next();
            length++;
        }
        return new j(objArrCopyOf);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final g builder() {
        return new g(this, null, this.b, 0);
    }

    @Override // java.util.List
    public final Object get(int i) {
        I4.b(i, a());
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
        I4.c(i, objArr.length);
        return new d(objArr, i, objArr.length);
    }

    @Override // kotlin.collections.AbstractC4916g, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c set(int i, Object obj) {
        I4.b(i, a());
        Object[] objArr = this.b;
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        objArrCopyOf[i] = obj;
        return new j(objArrCopyOf);
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c y(int i) {
        Object[] objArr = this.b;
        I4.b(i, objArr.length);
        if (objArr.length == 1) {
            return c;
        }
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length - 1);
        Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
        C4930v.h(objArr, i, objArrCopyOf, i + 1, objArr.length);
        return new j(objArrCopyOf);
    }

    @Override // java.util.Collection, java.util.List, androidx.compose.runtime.external.kotlinx.collections.immutable.c
    public final androidx.compose.runtime.external.kotlinx.collections.immutable.c add(Object obj) {
        Object[] objArr = this.b;
        if (objArr.length < 32) {
            Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length + 1);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            objArrCopyOf[objArr.length] = obj;
            return new j(objArrCopyOf);
        }
        Object[] objArr2 = new Object[32];
        objArr2[0] = obj;
        return new f(objArr, objArr2, objArr.length + 1, 0);
    }
}
