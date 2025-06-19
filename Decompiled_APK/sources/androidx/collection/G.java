package androidx.collection;

import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class G {
    public Object[] a;
    public int b;
    public E c;

    public G(int i) {
        this.a = i == 0 ? P.a : new Object[i];
    }

    public final void a(Object obj) {
        int i = this.b + 1;
        Object[] objArr = this.a;
        if (objArr.length < i) {
            h(i, objArr);
        }
        Object[] objArr2 = this.a;
        int i2 = this.b;
        objArr2[i2] = obj;
        this.b = i2 + 1;
    }

    public final Object b() {
        if (!e()) {
            return this.a[0];
        }
        androidx.collection.internal.a.e("ObjectList is empty.");
        throw null;
    }

    public final Object c(int i) {
        if (i >= 0 && i < this.b) {
            return this.a[i];
        }
        i(i);
        throw null;
    }

    public final int d(Object obj) {
        int i = 0;
        if (obj == null) {
            Object[] objArr = this.a;
            int i2 = this.b;
            while (i < i2) {
                if (objArr[i] == null) {
                    return i;
                }
                i++;
            }
            return -1;
        }
        Object[] objArr2 = this.a;
        int i3 = this.b;
        while (i < i3) {
            if (obj.equals(objArr2[i])) {
                return i;
            }
            i++;
        }
        return -1;
    }

    public final boolean e() {
        return this.b == 0;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof G) {
            G g = (G) obj;
            int i = g.b;
            int i2 = this.b;
            if (i == i2) {
                Object[] objArr = this.a;
                Object[] objArr2 = g.a;
                IntRange intRangeH = kotlin.ranges.l.h(0, i2);
                int i3 = intRangeH.a;
                int i4 = intRangeH.b;
                if (i3 > i4) {
                    return true;
                }
                while (Intrinsics.b(objArr[i3], objArr2[i3])) {
                    if (i3 == i4) {
                        return true;
                    }
                    i3++;
                }
                return false;
            }
        }
        return false;
    }

    public final boolean f(Object obj) {
        int iD = d(obj);
        if (iD < 0) {
            return false;
        }
        g(iD);
        return true;
    }

    public final Object g(int i) {
        int i2;
        if (i < 0 || i >= (i2 = this.b)) {
            i(i);
            throw null;
        }
        Object[] objArr = this.a;
        Object obj = objArr[i];
        if (i != i2 - 1) {
            C4930v.h(objArr, i, objArr, i + 1, i2);
        }
        int i3 = this.b - 1;
        this.b = i3;
        objArr[i3] = null;
        return obj;
    }

    public final void h(int i, Object[] oldContent) {
        Intrinsics.checkNotNullParameter(oldContent, "oldContent");
        int length = oldContent.length;
        Object[] objArr = new Object[Math.max(i, (length * 3) / 2)];
        C4930v.h(oldContent, 0, objArr, 0, length);
        this.a = objArr;
    }

    public final int hashCode() {
        Object[] objArr = this.a;
        int i = this.b;
        int iHashCode = 0;
        for (int i2 = 0; i2 < i; i2++) {
            Object obj = objArr[i2];
            iHashCode += (obj != null ? obj.hashCode() : 0) * 31;
        }
        return iHashCode;
    }

    public final void i(int i) {
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "Index ", " must be in 0..");
        sbV.append(this.b - 1);
        androidx.collection.internal.a.d(sbV.toString());
        throw null;
    }

    public final String toString() {
        androidx.camera.lifecycle.f fVar = new androidx.camera.lifecycle.f(this, 1);
        Intrinsics.checkNotNullParameter(", ", "separator");
        Intrinsics.checkNotNullParameter("[", "prefix");
        Intrinsics.checkNotNullParameter("]", "postfix");
        Intrinsics.checkNotNullParameter("...", "truncated");
        StringBuilder sb = new StringBuilder("[");
        Object[] objArr = this.a;
        int i = this.b;
        int i2 = 0;
        while (true) {
            if (i2 >= i) {
                sb.append((CharSequence) "]");
                break;
            }
            Object obj = objArr[i2];
            if (i2 == -1) {
                sb.append((CharSequence) "...");
                break;
            }
            if (i2 != 0) {
                sb.append((CharSequence) ", ");
            }
            sb.append((CharSequence) fVar.invoke(obj));
            i2++;
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public /* synthetic */ G() {
        this(16);
    }
}
