package androidx.compose.runtime.collection;

import androidx.collection.G;
import androidx.collection.I;
import androidx.collection.P;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.X;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.ranges.l;

/* loaded from: classes.dex */
public final class a {
    public final I a;

    public /* synthetic */ a(I i) {
        this.a = i;
    }

    public static final void a(I i, Object obj, Object obj2) {
        int iE = i.e(obj);
        boolean z = iE < 0;
        Object obj3 = z ? null : i.c[iE];
        if ((obj3 instanceof List) && (obj3 instanceof kotlin.jvm.internal.markers.a)) {
            boolean z2 = obj3 instanceof kotlin.jvm.internal.markers.c;
        }
        if (obj3 != null) {
            if (obj3 instanceof G) {
                G g = (G) obj3;
                g.a(obj2);
                obj2 = g;
            } else {
                Object[] objArr = P.a;
                G g2 = new G(2);
                g2.a(obj3);
                g2.a(obj2);
                obj2 = g2;
            }
        }
        if (!z) {
            i.c[iE] = obj2;
            return;
        }
        int i2 = ~iE;
        i.b[i2] = obj;
        i.c[i2] = obj2;
    }

    public static final Object b(I i, X x) {
        Object objF = i.f(x);
        if (objF == null) {
            return null;
        }
        if (!(objF instanceof G)) {
            i.h(x);
            return objF;
        }
        G g = (G) objF;
        if (g.e()) {
            throw new NoSuchElementException("List is empty.");
        }
        int i2 = g.b - 1;
        Object objC = g.c(i2);
        g.g(i2);
        Intrinsics.e(objC, "null cannot be cast to non-null type V of androidx.compose.runtime.collection.MultiValueMap");
        if (g.e()) {
            i.h(x);
        }
        if (g.b == 1) {
            i.j(x, g.b());
        }
        return objC;
    }

    public static final void c(I i, X x, C0775b0 c0775b0) {
        Object objF = i.f(x);
        if (objF != null) {
            if (!(objF instanceof G)) {
                if (((Boolean) c0775b0.invoke(objF)).booleanValue()) {
                    i.h(x);
                    return;
                }
                return;
            }
            G g = (G) objF;
            int i2 = g.b;
            Object[] objArr = g.a;
            int i3 = 0;
            IntRange intRangeH = l.h(0, i2);
            int i4 = intRangeH.a;
            int i5 = intRangeH.b;
            if (i4 <= i5) {
                while (true) {
                    objArr[i4 - i3] = objArr[i4];
                    if (((Boolean) c0775b0.invoke(objArr[i4])).booleanValue()) {
                        i3++;
                    }
                    if (i4 == i5) {
                        break;
                    } else {
                        i4++;
                    }
                }
            }
            C4930v.o(objArr, null, i2 - i3, i2);
            g.b -= i3;
            if (g.e()) {
                i.h(x);
            }
            if (g.b == 0) {
                i.j(x, g.b());
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x008e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.collection.G d(androidx.collection.I r15) {
        /*
            int r0 = r15.e
            if (r0 != 0) goto Lc
            androidx.collection.G r15 = androidx.collection.P.b
            java.lang.String r0 = "null cannot be cast to non-null type androidx.collection.ObjectList<E of androidx.collection.ObjectListKt.emptyObjectList>"
            kotlin.jvm.internal.Intrinsics.e(r15, r0)
            return r15
        Lc:
            androidx.collection.G r0 = new androidx.collection.G
            r0.<init>()
            java.lang.Object[] r1 = r15.c
            long[] r15 = r15.a
            int r2 = r15.length
            int r2 = r2 + (-2)
            if (r2 < 0) goto L93
            r3 = 0
            r4 = r3
        L1c:
            r5 = r15[r4]
            long r7 = ~r5
            r9 = 7
            long r7 = r7 << r9
            long r7 = r7 & r5
            r9 = -9187201950435737472(0x8080808080808080, double:-2.937446524422997E-306)
            long r7 = r7 & r9
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 == 0) goto L8e
            int r7 = r4 - r2
            int r7 = ~r7
            int r7 = r7 >>> 31
            r8 = 8
            int r7 = 8 - r7
            r9 = r3
        L36:
            if (r9 >= r7) goto L8c
            r10 = 255(0xff, double:1.26E-321)
            long r10 = r10 & r5
            r12 = 128(0x80, double:6.3E-322)
            int r10 = (r10 > r12 ? 1 : (r10 == r12 ? 0 : -1))
            if (r10 >= 0) goto L88
            int r10 = r4 << 3
            int r10 = r10 + r9
            r10 = r1[r10]
            boolean r11 = r10 instanceof androidx.collection.G
            if (r11 == 0) goto L80
            java.lang.String r11 = "null cannot be cast to non-null type androidx.collection.MutableObjectList<V of androidx.compose.runtime.collection.MultiValueMap>"
            kotlin.jvm.internal.Intrinsics.e(r10, r11)
            androidx.collection.G r10 = (androidx.collection.G) r10
            java.lang.String r11 = "elements"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r11)
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r10, r11)
            boolean r11 = r10.e()
            if (r11 == 0) goto L60
            goto L88
        L60:
            int r11 = r0.b
            int r12 = r10.b
            int r11 = r11 + r12
            java.lang.Object[] r12 = r0.a
            int r13 = r12.length
            if (r13 >= r11) goto L6d
            r0.h(r11, r12)
        L6d:
            java.lang.Object[] r11 = r0.a
            java.lang.Object[] r12 = r10.a
            int r13 = r0.b
            int r14 = r10.b
            kotlin.collections.C4930v.h(r12, r13, r11, r3, r14)
            int r11 = r0.b
            int r10 = r10.b
            int r11 = r11 + r10
            r0.b = r11
            goto L88
        L80:
            java.lang.String r11 = "null cannot be cast to non-null type V of androidx.compose.runtime.collection.MultiValueMap"
            kotlin.jvm.internal.Intrinsics.e(r10, r11)
            r0.a(r10)
        L88:
            long r5 = r5 >> r8
            int r9 = r9 + 1
            goto L36
        L8c:
            if (r7 != r8) goto L93
        L8e:
            if (r4 == r2) goto L93
            int r4 = r4 + 1
            goto L1c
        L93:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.collection.a.d(androidx.collection.I):androidx.collection.G");
    }

    public final boolean equals(Object obj) {
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MultiValueMap(map=" + this.a + ')';
    }
}
