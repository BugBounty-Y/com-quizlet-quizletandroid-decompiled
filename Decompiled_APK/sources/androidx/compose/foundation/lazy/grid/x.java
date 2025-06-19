package androidx.compose.foundation.lazy.grid;

import androidx.compose.foundation.lazy.layout.C0435g;
import java.util.ArrayList;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class x {
    public final i a;
    public final ArrayList b;
    public int c;
    public int d;
    public int e;
    public int f;
    public final ArrayList g;
    public Object h;
    public int i;

    public x(i iVar) {
        this.a = iVar;
        ArrayList arrayList = new ArrayList();
        arrayList.add(new u(0, 0));
        this.b = arrayList;
        this.f = -1;
        this.g = new ArrayList();
        this.h = K.a;
    }

    public final int a() {
        return ((int) Math.sqrt((d() * 1.0d) / this.i)) + 1;
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00a1  */
    /* JADX WARN: Type inference failed for: r4v15, types: [java.lang.Object, java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.android.billingclient.api.s b(int r13) {
        /*
            Method dump skipped, instructions count: 335
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.lazy.grid.x.b(int):com.android.billingclient.api.s");
    }

    public final int c(int i) {
        int i2;
        if (d() <= 0) {
            return 0;
        }
        if (i >= d()) {
            throw new IllegalArgumentException("ItemIndex > total count");
        }
        if (!this.a.d) {
            return i / this.i;
        }
        ArrayList arrayList = this.b;
        w comparison = new w(i, 0);
        int size = arrayList.size();
        Intrinsics.checkNotNullParameter(arrayList, "<this>");
        Intrinsics.checkNotNullParameter(comparison, "comparison");
        kotlin.collections.B.m(arrayList.size(), size);
        int i3 = size - 1;
        int i4 = 0;
        while (true) {
            if (i4 > i3) {
                i2 = -(i4 + 1);
                break;
            }
            i2 = (i4 + i3) >>> 1;
            int iIntValue = ((Number) comparison.invoke(arrayList.get(i2))).intValue();
            if (iIntValue >= 0) {
                if (iIntValue <= 0) {
                    break;
                }
                i3 = i2 - 1;
            } else {
                i4 = i2 + 1;
            }
        }
        if (i2 < 0) {
            i2 = (-i2) - 2;
        }
        int iA = a() * i2;
        int i5 = ((u) arrayList.get(i2)).a;
        if (i5 > i) {
            throw new IllegalArgumentException("currentItemIndex > itemIndex");
        }
        int i6 = 0;
        while (i5 < i) {
            int i7 = i5 + 1;
            int iE = e(i5);
            i6 += iE;
            int i8 = this.i;
            if (i6 >= i8) {
                if (i6 == i8) {
                    iA++;
                    i6 = 0;
                } else {
                    iA++;
                    i6 = iE;
                }
            }
            if (iA % a() == 0 && iA / a() >= arrayList.size()) {
                arrayList.add(new u(i7 - (i6 > 0 ? 1 : 0), 0));
            }
            i5 = i7;
        }
        return e(i) + i6 > this.i ? iA + 1 : iA;
    }

    public final int d() {
        return this.a.c.b;
    }

    public final int e(int i) {
        v vVar = v.a;
        C0435g c0435gO = this.a.c.o(i);
        return (int) ((C0427b) ((f) c0435gO.c).b.invoke(vVar, Integer.valueOf(i - c0435gO.a))).a;
    }
}
