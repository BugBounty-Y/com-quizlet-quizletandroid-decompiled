package androidx.room;

import java.util.Set;
import kotlin.collections.M;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l {
    public final k a;
    public final int[] b;
    public final String[] c;
    public final Set d;

    public l(k observer, int[] tableIds, String[] tableNames) {
        Intrinsics.checkNotNullParameter(observer, "observer");
        Intrinsics.checkNotNullParameter(tableIds, "tableIds");
        Intrinsics.checkNotNullParameter(tableNames, "tableNames");
        this.a = observer;
        this.b = tableIds;
        this.c = tableNames;
        this.d = tableNames.length == 0 ? M.a : Z.b(tableNames[0]);
        if (tableIds.length != tableNames.length) {
            throw new IllegalStateException("Check failed.");
        }
    }

    public final void a(Set invalidatedTablesIds) {
        Set setA;
        Intrinsics.checkNotNullParameter(invalidatedTablesIds, "invalidatedTablesIds");
        int[] iArr = this.b;
        int length = iArr.length;
        if (length != 0) {
            int i = 0;
            if (length != 1) {
                kotlin.collections.builders.p pVar = new kotlin.collections.builders.p();
                int length2 = iArr.length;
                int i2 = 0;
                while (i < length2) {
                    int i3 = i2 + 1;
                    if (invalidatedTablesIds.contains(Integer.valueOf(iArr[i]))) {
                        pVar.add(this.c[i2]);
                    }
                    i++;
                    i2 = i3;
                }
                setA = Z.a(pVar);
            } else {
                setA = invalidatedTablesIds.contains(Integer.valueOf(iArr[0])) ? this.d : M.a;
            }
        } else {
            setA = M.a;
        }
        if (setA.isEmpty()) {
            return;
        }
        this.a.a(setA);
    }
}
