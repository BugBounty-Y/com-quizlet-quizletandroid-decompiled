package androidx.compose.ui.window;

import androidx.compose.animation.C;
import androidx.compose.animation.C0293u;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.V;

/* loaded from: classes.dex */
public final class e implements K {
    public static final e b = new e(0);
    public static final e c = new e(1);
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v14 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v5 */
    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        Object obj;
        int iMax;
        switch (this.a) {
            case 0:
                ArrayList arrayList = new ArrayList(list.size());
                int size = list.size();
                for (int i = 0; i < size; i++) {
                    arrayList.add(((J) list.get(i)).B(j));
                }
                int i2 = 1;
                W w = null;
                if (arrayList.isEmpty()) {
                    obj = null;
                } else {
                    obj = arrayList.get(0);
                    int i3 = ((W) obj).a;
                    int i4 = B.i(arrayList);
                    if (1 <= i4) {
                        int i5 = 1;
                        while (true) {
                            Object obj2 = arrayList.get(i5);
                            int i6 = ((W) obj2).a;
                            if (i3 < i6) {
                                obj = obj2;
                                i3 = i6;
                            }
                            if (i5 != i4) {
                                i5++;
                            }
                        }
                    }
                }
                W w2 = (W) obj;
                int iJ = w2 != null ? w2.a : androidx.compose.ui.unit.a.j(j);
                if (!arrayList.isEmpty()) {
                    ?? r2 = arrayList.get(0);
                    int i7 = ((W) r2).b;
                    int i8 = B.i(arrayList);
                    boolean z = r2;
                    if (1 <= i8) {
                        while (true) {
                            Object obj3 = arrayList.get(i2);
                            int i9 = ((W) obj3).b;
                            r2 = z;
                            if (i7 < i9) {
                                r2 = obj3;
                                i7 = i9;
                            }
                            if (i2 != i8) {
                                i2++;
                                z = r2;
                            }
                        }
                    }
                    w = r2;
                }
                W w3 = w;
                return m.n0(iJ, w3 != null ? w3.b : androidx.compose.ui.unit.a.i(j), V.c(), new C0293u(4, arrayList));
            default:
                int size2 = list.size();
                int i10 = 0;
                if (size2 == 0) {
                    return m.n0(0, 0, V.c(), c.f);
                }
                if (size2 == 1) {
                    W wB = ((J) list.get(0)).B(j);
                    return m.n0(wB.a, wB.b, V.c(), new C(wB, 15));
                }
                ArrayList arrayList2 = new ArrayList(list.size());
                int size3 = list.size();
                for (int i11 = 0; i11 < size3; i11++) {
                    arrayList2.add(((J) list.get(i11)).B(j));
                }
                int i12 = B.i(arrayList2);
                if (i12 >= 0) {
                    int iMax2 = 0;
                    iMax = 0;
                    while (true) {
                        W w4 = (W) arrayList2.get(i10);
                        iMax2 = Math.max(iMax2, w4.a);
                        iMax = Math.max(iMax, w4.b);
                        if (i10 != i12) {
                            i10++;
                        } else {
                            i10 = iMax2;
                        }
                    }
                } else {
                    iMax = 0;
                }
                return m.n0(i10, iMax, V.c(), new C0293u(5, arrayList2));
        }
    }
}
