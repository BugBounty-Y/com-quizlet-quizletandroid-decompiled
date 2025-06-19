package androidx.recyclerview.widget;

import android.util.SparseArray;
import android.util.SparseIntArray;
import android.view.View;
import androidx.collection.C0219q;
import androidx.compose.material3.C0676l1;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes.dex */
public final class N0 implements R0 {
    public Object a;
    public Object b;

    public N0(C1377l0 c1377l0) {
        this.a = c1377l0;
        P0 p0 = new P0();
        p0.a = 0;
        this.b = p0;
    }

    public static int g(int i, int i2) {
        int i3 = 0;
        int i4 = 0;
        for (int i5 = 0; i5 < i; i5++) {
            i3++;
            if (i3 == i2) {
                i4++;
                i3 = 0;
            } else if (i3 > i2) {
                i4++;
                i3 = 1;
            }
        }
        return i3 + 1 > i2 ? i4 + 1 : i4;
    }

    @Override // androidx.recyclerview.widget.R0
    public int a(int i) {
        return i;
    }

    public void b(F0 f0, C0676l1 c0676l1) {
        androidx.collection.V v = (androidx.collection.V) this.a;
        Q0 q0A = (Q0) v.get(f0);
        if (q0A == null) {
            q0A = Q0.a();
            v.put(f0, q0A);
        }
        q0A.c = c0676l1;
        q0A.a |= 8;
    }

    @Override // androidx.recyclerview.widget.R0
    public int c(int i) {
        C1356b c1356b = (C1356b) this.b;
        List arrayList = (List) ((SparseArray) c1356b.a).get(i);
        if (arrayList == null) {
            arrayList = new ArrayList();
            ((SparseArray) c1356b.a).put(i, arrayList);
        }
        X x = (X) this.a;
        if (!arrayList.contains(x)) {
            arrayList.add(x);
        }
        return i;
    }

    public void d() {
        int[] iArr = (int[]) this.a;
        if (iArr != null) {
            Arrays.fill(iArr, -1);
        }
        this.b = null;
    }

    @Override // androidx.recyclerview.widget.R0
    public void dispose() {
        SparseArray sparseArray = (SparseArray) ((C1356b) this.b).a;
        for (int size = sparseArray.size() - 1; size >= 0; size--) {
            List list = (List) sparseArray.valueAt(size);
            if (list.remove((X) this.a) && list.isEmpty()) {
                sparseArray.removeAt(size);
            }
        }
    }

    public void e(int i) {
        int[] iArr = (int[]) this.a;
        if (iArr == null) {
            int[] iArr2 = new int[Math.max(i, 10) + 1];
            this.a = iArr2;
            Arrays.fill(iArr2, -1);
        } else if (i >= iArr.length) {
            int length = iArr.length;
            while (length <= i) {
                length *= 2;
            }
            int[] iArr3 = new int[length];
            this.a = iArr3;
            System.arraycopy(iArr, 0, iArr3, 0, iArr.length);
            int[] iArr4 = (int[]) this.a;
            Arrays.fill(iArr4, iArr.length, iArr4.length, -1);
        }
    }

    public View f(int i, int i2, int i3, int i4) {
        View viewU;
        C1377l0 c1377l0 = (C1377l0) this.a;
        int iD = c1377l0.d();
        int iC = c1377l0.c();
        int i5 = i2 > i ? 1 : -1;
        View view = null;
        while (i != i2) {
            switch (c1377l0.a) {
                case 0:
                    viewU = c1377l0.b.u(i);
                    break;
                default:
                    viewU = c1377l0.b.u(i);
                    break;
            }
            int iB = c1377l0.b(viewU);
            int iA = c1377l0.a(viewU);
            P0 p0 = (P0) this.b;
            p0.b = iD;
            p0.c = iC;
            p0.d = iB;
            p0.e = iA;
            if (i3 != 0) {
                p0.a = i3;
                if (p0.a()) {
                    return viewU;
                }
            }
            if (i4 != 0) {
                p0.a = i4;
                if (p0.a()) {
                    view = viewU;
                }
            }
            i += i5;
        }
        return view;
    }

    public void h() {
        ((SparseIntArray) this.a).clear();
    }

    public boolean i(View view) {
        C1377l0 c1377l0 = (C1377l0) this.a;
        int iD = c1377l0.d();
        int iC = c1377l0.c();
        int iB = c1377l0.b(view);
        int iA = c1377l0.a(view);
        P0 p0 = (P0) this.b;
        p0.b = iD;
        p0.c = iC;
        p0.d = iB;
        p0.e = iA;
        p0.a = 24579;
        return p0.a();
    }

    public void j(int i, int i2) {
        int[] iArr = (int[]) this.a;
        if (iArr == null || i >= iArr.length) {
            return;
        }
        int i3 = i + i2;
        e(i3);
        int[] iArr2 = (int[]) this.a;
        System.arraycopy(iArr2, i, iArr2, i3, (iArr2.length - i) - i2);
        Arrays.fill((int[]) this.a, i, i3, -1);
        ArrayList arrayList = (ArrayList) this.b;
        if (arrayList == null) {
            return;
        }
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            StaggeredGridLayoutManager$LazySpanLookup$FullSpanItem staggeredGridLayoutManager$LazySpanLookup$FullSpanItem = (StaggeredGridLayoutManager$LazySpanLookup$FullSpanItem) ((ArrayList) this.b).get(size);
            int i4 = staggeredGridLayoutManager$LazySpanLookup$FullSpanItem.a;
            if (i4 >= i) {
                staggeredGridLayoutManager$LazySpanLookup$FullSpanItem.a = i4 + i2;
            }
        }
    }

    public void k(int i, int i2) {
        int[] iArr = (int[]) this.a;
        if (iArr == null || i >= iArr.length) {
            return;
        }
        int i3 = i + i2;
        e(i3);
        int[] iArr2 = (int[]) this.a;
        System.arraycopy(iArr2, i3, iArr2, i, (iArr2.length - i) - i2);
        int[] iArr3 = (int[]) this.a;
        Arrays.fill(iArr3, iArr3.length - i2, iArr3.length, -1);
        ArrayList arrayList = (ArrayList) this.b;
        if (arrayList == null) {
            return;
        }
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            StaggeredGridLayoutManager$LazySpanLookup$FullSpanItem staggeredGridLayoutManager$LazySpanLookup$FullSpanItem = (StaggeredGridLayoutManager$LazySpanLookup$FullSpanItem) ((ArrayList) this.b).get(size);
            int i4 = staggeredGridLayoutManager$LazySpanLookup$FullSpanItem.a;
            if (i4 >= i) {
                if (i4 < i3) {
                    ((ArrayList) this.b).remove(size);
                } else {
                    staggeredGridLayoutManager$LazySpanLookup$FullSpanItem.a = i4 - i2;
                }
            }
        }
    }

    public C0676l1 l(F0 f0, int i) {
        Q0 q0;
        C0676l1 c0676l1;
        androidx.collection.V v = (androidx.collection.V) this.a;
        int iE = v.e(f0);
        if (iE >= 0 && (q0 = (Q0) v.k(iE)) != null) {
            int i2 = q0.a;
            if ((i2 & i) != 0) {
                int i3 = i2 & (~i);
                q0.a = i3;
                if (i == 4) {
                    c0676l1 = q0.b;
                } else {
                    if (i != 8) {
                        throw new IllegalArgumentException("Must provide flag PRE or POST");
                    }
                    c0676l1 = q0.c;
                }
                if ((i3 & 12) == 0) {
                    v.i(iE);
                    q0.a = 0;
                    q0.b = null;
                    q0.c = null;
                    Q0.d.c(q0);
                }
                return c0676l1;
            }
        }
        return null;
    }

    public void m(F0 f0) {
        Q0 q0 = (Q0) ((androidx.collection.V) this.a).get(f0);
        if (q0 == null) {
            return;
        }
        q0.a &= -2;
    }

    public void n(F0 f0) {
        C0219q c0219q = (C0219q) this.b;
        int i = c0219q.i() - 1;
        while (true) {
            if (i < 0) {
                break;
            }
            if (f0 == c0219q.k(i)) {
                Object[] objArr = c0219q.c;
                Object obj = objArr[i];
                Object obj2 = androidx.collection.r.a;
                if (obj != obj2) {
                    objArr[i] = obj2;
                    c0219q.a = true;
                }
            } else {
                i--;
            }
        }
        Q0 q0 = (Q0) ((androidx.collection.V) this.a).remove(f0);
        if (q0 != null) {
            q0.a = 0;
            q0.b = null;
            q0.c = null;
            Q0.d.c(q0);
        }
    }

    public N0(int i) {
        switch (i) {
            case 4:
                this.a = new androidx.collection.V(0);
                this.b = new C0219q((Object) null);
                break;
            default:
                this.a = new SparseIntArray();
                this.b = new SparseIntArray();
                break;
        }
    }
}
