package androidx.compose.foundation.lazy.grid;

import java.util.List;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class s {
    public final int a;
    public final r[] b;
    public final t c;
    public final Object d;
    public final int e;
    public final int f;
    public final int g;

    public s(int i, r[] rVarArr, t tVar, List list, int i2) {
        this.a = i;
        this.b = rVarArr;
        this.c = tVar;
        this.d = list;
        this.e = i2;
        int iMax = 0;
        for (r rVar : rVarArr) {
            iMax = Math.max(iMax, rVar.n);
        }
        this.f = iMax;
        int i3 = iMax + this.e;
        this.g = i3 >= 0 ? i3 : 0;
    }

    /* JADX WARN: Type inference failed for: r5v0, types: [java.lang.Object, java.util.List] */
    public final r[] a(int i, int i2, int i3) {
        r[] rVarArr = this.b;
        int length = rVarArr.length;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        while (i4 < length) {
            r rVar = rVarArr[i4];
            int i7 = i5 + 1;
            int i8 = (int) ((C0427b) this.d.get(i5)).a;
            int i9 = i;
            rVar.k(i9, this.c.b[i6], i2, i3, this.a, i6);
            Unit unit = Unit.a;
            i6 += i8;
            i4++;
            i = i9;
            i5 = i7;
        }
        return rVarArr;
    }
}
