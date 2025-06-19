package kotlin.collections.builders;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3324c;
import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import kotlin.collections.AbstractC4916g;
import kotlin.collections.C4913d;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class h implements Map, Serializable, kotlin.jvm.internal.markers.e {

    @NotNull
    public static final e n = new e(null);
    public static final h o;
    public Object[] a;
    public Object[] b;
    public int[] c;
    public int[] d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public j j;
    public androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j k;
    public i l;
    public boolean m;

    static {
        h hVar = new h(0);
        hVar.m = true;
        o = hVar;
    }

    public h() {
        this(8);
    }

    private final Object writeReplace() throws NotSerializableException {
        if (this.m) {
            return new n(this);
        }
        throw new NotSerializableException("The map cannot be serialized while it is being built.");
    }

    public final int a(Object obj) {
        d();
        while (true) {
            int iL = l(obj);
            int i = this.e * 2;
            int length = this.d.length / 2;
            if (i > length) {
                i = length;
            }
            int i2 = 0;
            while (true) {
                int[] iArr = this.d;
                int i3 = iArr[iL];
                if (i3 <= 0) {
                    int i4 = this.f;
                    Object[] objArr = this.a;
                    if (i4 < objArr.length) {
                        int i5 = i4 + 1;
                        this.f = i5;
                        objArr[i4] = obj;
                        this.c[i4] = iL;
                        iArr[iL] = i5;
                        this.i++;
                        this.h++;
                        if (i2 > this.e) {
                            this.e = i2;
                        }
                        return i4;
                    }
                    h(1);
                } else {
                    if (Intrinsics.b(this.a[i3 - 1], obj)) {
                        return -i3;
                    }
                    i2++;
                    if (i2 > i) {
                        m(this.d.length * 2);
                        break;
                    }
                    iL = iL == 0 ? this.d.length - 1 : iL - 1;
                }
            }
        }
    }

    public final h b() {
        d();
        this.m = true;
        if (this.i > 0) {
            return this;
        }
        h hVar = o;
        Intrinsics.e(hVar, "null cannot be cast to non-null type kotlin.collections.Map<K of kotlin.collections.builders.MapBuilder, V of kotlin.collections.builders.MapBuilder>");
        return hVar;
    }

    @Override // java.util.Map
    public final void clear() {
        d();
        int i = this.f - 1;
        if (i >= 0) {
            int i2 = 0;
            while (true) {
                int[] iArr = this.c;
                int i3 = iArr[i2];
                if (i3 >= 0) {
                    this.d[i3] = 0;
                    iArr[i2] = -1;
                }
                if (i2 == i) {
                    break;
                } else {
                    i2++;
                }
            }
        }
        AbstractC3324c.g(0, this.f, this.a);
        Object[] objArr = this.b;
        if (objArr != null) {
            AbstractC3324c.g(0, this.f, objArr);
        }
        this.i = 0;
        this.f = 0;
        this.h++;
    }

    @Override // java.util.Map
    public final boolean containsKey(Object obj) {
        return j(obj) >= 0;
    }

    @Override // java.util.Map
    public final boolean containsValue(Object obj) {
        return k(obj) >= 0;
    }

    public final void d() {
        if (this.m) {
            throw new UnsupportedOperationException();
        }
    }

    public final void e(boolean z) {
        int i;
        Object[] objArr = this.b;
        int i2 = 0;
        int i3 = 0;
        while (true) {
            i = this.f;
            if (i2 >= i) {
                break;
            }
            int[] iArr = this.c;
            int i4 = iArr[i2];
            if (i4 >= 0) {
                Object[] objArr2 = this.a;
                objArr2[i3] = objArr2[i2];
                if (objArr != null) {
                    objArr[i3] = objArr[i2];
                }
                if (z) {
                    iArr[i3] = i4;
                    this.d[i4] = i3 + 1;
                }
                i3++;
            }
            i2++;
        }
        AbstractC3324c.g(i3, i, this.a);
        if (objArr != null) {
            AbstractC3324c.g(i3, this.f, objArr);
        }
        this.f = i3;
    }

    @Override // java.util.Map
    public final Set entrySet() {
        i iVar = this.l;
        if (iVar != null) {
            return iVar;
        }
        i iVar2 = new i(this);
        this.l = iVar2;
        return iVar2;
    }

    @Override // java.util.Map
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        Map map = (Map) obj;
        return this.i == map.size() && f(map.entrySet());
    }

    public final boolean f(Collection m) {
        Intrinsics.checkNotNullParameter(m, "m");
        for (Object obj : m) {
            if (obj != null) {
                try {
                    if (!g((Map.Entry) obj)) {
                    }
                } catch (ClassCastException unused) {
                }
            }
            return false;
        }
        return true;
    }

    public final boolean g(Map.Entry entry) {
        Intrinsics.checkNotNullParameter(entry, "entry");
        int iJ = j(entry.getKey());
        if (iJ < 0) {
            return false;
        }
        Object[] objArr = this.b;
        Intrinsics.d(objArr);
        return Intrinsics.b(objArr[iJ], entry.getValue());
    }

    @Override // java.util.Map
    public final Object get(Object obj) {
        int iJ = j(obj);
        if (iJ < 0) {
            return null;
        }
        Object[] objArr = this.b;
        Intrinsics.d(objArr);
        return objArr[iJ];
    }

    public final void h(int i) {
        Object[] objArrCopyOf;
        Object[] objArr = this.a;
        int length = objArr.length;
        int i2 = this.f;
        int i3 = length - i2;
        int i4 = i2 - this.i;
        if (i3 < i && i3 + i4 >= i && i4 >= objArr.length / 4) {
            e(true);
            return;
        }
        int i5 = i2 + i;
        if (i5 < 0) {
            throw new OutOfMemoryError();
        }
        if (i5 > objArr.length) {
            C4913d c4913d = AbstractC4916g.a;
            int length2 = objArr.length;
            c4913d.getClass();
            int iE = C4913d.e(length2, i5);
            Object[] objArr2 = this.a;
            Intrinsics.checkNotNullParameter(objArr2, "<this>");
            Object[] objArrCopyOf2 = Arrays.copyOf(objArr2, iE);
            Intrinsics.checkNotNullExpressionValue(objArrCopyOf2, "copyOf(...)");
            this.a = objArrCopyOf2;
            Object[] objArr3 = this.b;
            if (objArr3 != null) {
                Intrinsics.checkNotNullParameter(objArr3, "<this>");
                objArrCopyOf = Arrays.copyOf(objArr3, iE);
                Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(...)");
            } else {
                objArrCopyOf = null;
            }
            this.b = objArrCopyOf;
            int[] iArrCopyOf = Arrays.copyOf(this.c, iE);
            Intrinsics.checkNotNullExpressionValue(iArrCopyOf, "copyOf(...)");
            this.c = iArrCopyOf;
            n.getClass();
            int iHighestOneBit = Integer.highestOneBit((iE >= 1 ? iE : 1) * 3);
            if (iHighestOneBit > this.d.length) {
                m(iHighestOneBit);
            }
        }
    }

    @Override // java.util.Map
    public final int hashCode() {
        Intrinsics.checkNotNullParameter(this, "map");
        f fVar = new f(this, 0);
        int i = 0;
        while (fVar.hasNext()) {
            int i2 = fVar.a;
            h hVar = (h) fVar.d;
            if (i2 >= hVar.f) {
                throw new NoSuchElementException();
            }
            fVar.a = i2 + 1;
            fVar.b = i2;
            Object obj = hVar.a[i2];
            int iHashCode = obj != null ? obj.hashCode() : 0;
            Object[] objArr = hVar.b;
            Intrinsics.d(objArr);
            Object obj2 = objArr[fVar.b];
            int iHashCode2 = obj2 != null ? obj2.hashCode() : 0;
            fVar.f();
            i += iHashCode ^ iHashCode2;
        }
        return i;
    }

    @Override // java.util.Map
    public final boolean isEmpty() {
        return this.i == 0;
    }

    public final int j(Object obj) {
        int iL = l(obj);
        int i = this.e;
        while (true) {
            int i2 = this.d[iL];
            if (i2 == 0) {
                return -1;
            }
            if (i2 > 0) {
                int i3 = i2 - 1;
                if (Intrinsics.b(this.a[i3], obj)) {
                    return i3;
                }
            }
            i--;
            if (i < 0) {
                return -1;
            }
            iL = iL == 0 ? this.d.length - 1 : iL - 1;
        }
    }

    public final int k(Object obj) {
        int i = this.f;
        while (true) {
            i--;
            if (i < 0) {
                return -1;
            }
            if (this.c[i] >= 0) {
                Object[] objArr = this.b;
                Intrinsics.d(objArr);
                if (Intrinsics.b(objArr[i], obj)) {
                    return i;
                }
            }
        }
    }

    @Override // java.util.Map
    public final Set keySet() {
        j jVar = this.j;
        if (jVar != null) {
            return jVar;
        }
        j jVar2 = new j(this);
        this.j = jVar2;
        return jVar2;
    }

    public final int l(Object obj) {
        return ((obj != null ? obj.hashCode() : 0) * (-1640531527)) >>> this.g;
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0037, code lost:
    
        r3[r0] = r6;
        r5.c[r2] = r0;
        r2 = r6;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m(int r6) {
        /*
            r5 = this;
            int r0 = r5.h
            int r0 = r0 + 1
            r5.h = r0
            int r0 = r5.f
            int r1 = r5.i
            r2 = 0
            if (r0 <= r1) goto L10
            r5.e(r2)
        L10:
            int[] r0 = new int[r6]
            r5.d = r0
            kotlin.collections.builders.e r0 = kotlin.collections.builders.h.n
            r0.getClass()
            int r6 = java.lang.Integer.numberOfLeadingZeros(r6)
            int r6 = r6 + 1
            r5.g = r6
        L21:
            int r6 = r5.f
            if (r2 >= r6) goto L55
            int r6 = r2 + 1
            java.lang.Object[] r0 = r5.a
            r0 = r0[r2]
            int r0 = r5.l(r0)
            int r1 = r5.e
        L31:
            int[] r3 = r5.d
            r4 = r3[r0]
            if (r4 != 0) goto L3f
            r3[r0] = r6
            int[] r1 = r5.c
            r1[r2] = r0
            r2 = r6
            goto L21
        L3f:
            int r1 = r1 + (-1)
            if (r1 < 0) goto L4d
            int r4 = r0 + (-1)
            if (r0 != 0) goto L4b
            int r0 = r3.length
            int r0 = r0 + (-1)
            goto L31
        L4b:
            r0 = r4
            goto L31
        L4d:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "This cannot happen with fixed magic multiplier and grow-only hash array. Have object hashCodes changed?"
            r6.<init>(r0)
            throw r6
        L55:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.collections.builders.h.m(int):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x006b A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:33:? A[LOOP:0: B:9:0x0027->B:33:?, LOOP_END, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void n(int r12) {
        /*
            r11 = this;
            java.lang.Object[] r0 = r11.a
            java.lang.String r1 = "<this>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            r2 = 0
            r0[r12] = r2
            java.lang.Object[] r0 = r11.b
            if (r0 == 0) goto L13
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r1)
            r0[r12] = r2
        L13:
            int[] r0 = r11.c
            r0 = r0[r12]
            int r1 = r11.e
            int r1 = r1 * 2
            int[] r2 = r11.d
            int r2 = r2.length
            int r2 = r2 / 2
            if (r1 <= r2) goto L23
            r1 = r2
        L23:
            r2 = 0
            r3 = r1
            r4 = r2
            r1 = r0
        L27:
            int r5 = r0 + (-1)
            if (r0 != 0) goto L31
            int[] r0 = r11.d
            int r0 = r0.length
            int r0 = r0 + (-1)
            goto L32
        L31:
            r0 = r5
        L32:
            int r4 = r4 + 1
            int r5 = r11.e
            r6 = -1
            if (r4 <= r5) goto L3e
            int[] r0 = r11.d
            r0[r1] = r2
            goto L6f
        L3e:
            int[] r5 = r11.d
            r7 = r5[r0]
            if (r7 != 0) goto L47
            r5[r1] = r2
            goto L6f
        L47:
            if (r7 >= 0) goto L4e
            r5[r1] = r6
        L4b:
            r1 = r0
            r4 = r2
            goto L68
        L4e:
            java.lang.Object[] r5 = r11.a
            int r8 = r7 + (-1)
            r5 = r5[r8]
            int r5 = r11.l(r5)
            int r5 = r5 - r0
            int[] r9 = r11.d
            int r10 = r9.length
            int r10 = r10 + (-1)
            r5 = r5 & r10
            if (r5 < r4) goto L68
            r9[r1] = r7
            int[] r4 = r11.c
            r4[r8] = r1
            goto L4b
        L68:
            int r3 = r3 + r6
            if (r3 >= 0) goto L27
            int[] r0 = r11.d
            r0[r1] = r6
        L6f:
            int[] r0 = r11.c
            r0[r12] = r6
            int r12 = r11.i
            int r12 = r12 + r6
            r11.i = r12
            int r12 = r11.h
            int r12 = r12 + 1
            r11.h = r12
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.collections.builders.h.n(int):void");
    }

    @Override // java.util.Map
    public final Object put(Object obj, Object obj2) {
        d();
        int iA = a(obj);
        Object[] objArr = this.b;
        if (objArr == null) {
            int length = this.a.length;
            if (length < 0) {
                throw new IllegalArgumentException("capacity must be non-negative.");
            }
            objArr = new Object[length];
            this.b = objArr;
        }
        if (iA >= 0) {
            objArr[iA] = obj2;
            return null;
        }
        int i = (-iA) - 1;
        Object obj3 = objArr[i];
        objArr[i] = obj2;
        return obj3;
    }

    @Override // java.util.Map
    public final void putAll(Map from) {
        Intrinsics.checkNotNullParameter(from, "from");
        d();
        Set<Map.Entry> setEntrySet = from.entrySet();
        if (setEntrySet.isEmpty()) {
            return;
        }
        h(setEntrySet.size());
        for (Map.Entry entry : setEntrySet) {
            int iA = a(entry.getKey());
            Object[] objArr = this.b;
            if (objArr == null) {
                int length = this.a.length;
                if (length < 0) {
                    throw new IllegalArgumentException("capacity must be non-negative.");
                }
                objArr = new Object[length];
                this.b = objArr;
            }
            if (iA >= 0) {
                objArr[iA] = entry.getValue();
            } else {
                int i = (-iA) - 1;
                if (!Intrinsics.b(entry.getValue(), objArr[i])) {
                    objArr[i] = entry.getValue();
                }
            }
        }
    }

    @Override // java.util.Map
    public final Object remove(Object obj) {
        d();
        int iJ = j(obj);
        if (iJ < 0) {
            return null;
        }
        Object[] objArr = this.b;
        Intrinsics.d(objArr);
        Object obj2 = objArr[iJ];
        n(iJ);
        return obj2;
    }

    @Override // java.util.Map
    public final int size() {
        return this.i;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder((this.i * 3) + 2);
        sb.append("{");
        Intrinsics.checkNotNullParameter(this, "map");
        f fVar = new f(this, 0);
        int i = 0;
        while (fVar.hasNext()) {
            if (i > 0) {
                sb.append(", ");
            }
            Intrinsics.checkNotNullParameter(sb, "sb");
            int i2 = fVar.a;
            h hVar = (h) fVar.d;
            if (i2 >= hVar.f) {
                throw new NoSuchElementException();
            }
            fVar.a = i2 + 1;
            fVar.b = i2;
            Object obj = hVar.a[i2];
            if (obj == hVar) {
                sb.append("(this Map)");
            } else {
                sb.append(obj);
            }
            sb.append('=');
            Object[] objArr = hVar.b;
            Intrinsics.d(objArr);
            Object obj2 = objArr[fVar.b];
            if (obj2 == hVar) {
                sb.append("(this Map)");
            } else {
                sb.append(obj2);
            }
            fVar.f();
            i++;
        }
        sb.append("}");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @Override // java.util.Map
    public final Collection values() {
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j jVar = this.k;
        if (jVar != null) {
            return jVar;
        }
        androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j jVar2 = new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j(this);
        this.k = jVar2;
        return jVar2;
    }

    public h(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("capacity must be non-negative.");
        }
        Object[] objArr = new Object[i];
        int[] iArr = new int[i];
        n.getClass();
        int iHighestOneBit = Integer.highestOneBit((i < 1 ? 1 : i) * 3);
        this.a = objArr;
        this.b = null;
        this.c = iArr;
        this.d = new int[iHighestOneBit];
        this.e = 2;
        this.f = 0;
        this.g = Integer.numberOfLeadingZeros(iHighestOneBit) + 1;
    }
}
