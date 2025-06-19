package androidx.compose.ui.focus;

import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.E;
import java.util.Comparator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class v implements Comparator {
    public static final v a = new v();

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v4, types: [java.lang.Object, java.lang.Object[]] */
    /* JADX WARN: Type inference failed for: r5v9, types: [java.lang.Object, java.lang.Object[]] */
    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        t tVar = (t) obj;
        t tVar2 = (t) obj2;
        int i = 0;
        if (a.v(tVar) && a.v(tVar2)) {
            E eV = AbstractC0910f.v(tVar);
            E eV2 = AbstractC0910f.v(tVar2);
            if (!Intrinsics.b(eV, eV2)) {
                E[] eArr = new E[16];
                int i2 = 0;
                while (eV != null) {
                    int i3 = i2 + 1;
                    if (eArr.length < i3) {
                        int length = eArr.length;
                        ?? r5 = new Object[Math.max(i3, length * 2)];
                        System.arraycopy(eArr, 0, r5, 0, length);
                        eArr = r5;
                    }
                    if (i2 != 0) {
                        System.arraycopy(eArr, 0, eArr, 0 + 1, i2 + 0);
                    }
                    eArr[0] = eV;
                    i2++;
                    eV = eV.s();
                }
                E[] eArr2 = new E[16];
                int i4 = 0;
                while (eV2 != null) {
                    int i5 = i4 + 1;
                    if (eArr2.length < i5) {
                        int length2 = eArr2.length;
                        ?? r52 = new Object[Math.max(i5, length2 * 2)];
                        System.arraycopy(eArr2, 0, r52, 0, length2);
                        eArr2 = r52;
                    }
                    if (i4 != 0) {
                        System.arraycopy(eArr2, 0, eArr2, 0 + 1, i4 + 0);
                    }
                    eArr2[0] = eV2;
                    i4++;
                    eV2 = eV2.s();
                }
                int iMin = Math.min(i2 - 1, i4 - 1);
                if (iMin >= 0) {
                    while (Intrinsics.b(eArr[i], eArr2[i])) {
                        if (i != iMin) {
                            i++;
                        }
                    }
                    return Intrinsics.g(eArr[i].t(), eArr2[i].t());
                }
                throw new IllegalStateException("Could not find a common ancestor between the two FocusModifiers.");
            }
        } else {
            if (a.v(tVar)) {
                return -1;
            }
            if (a.v(tVar2)) {
                return 1;
            }
        }
        return 0;
    }
}
