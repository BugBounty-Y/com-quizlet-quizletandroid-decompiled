package androidx.compose.foundation.text.selection;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.AbstractC0217o;
import androidx.collection.C0225x;
import java.util.ArrayList;
import java.util.NoSuchElementException;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.selection.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0531l implements I {
    public final C0225x a;
    public final ArrayList b;
    public final int c;
    public final int d;
    public final boolean e;
    public final C0536q f;

    public C0531l(C0225x c0225x, ArrayList arrayList, int i, int i2, boolean z, C0536q c0536q) {
        this.a = c0225x;
        this.b = arrayList;
        this.c = i;
        this.d = i2;
        this.e = z;
        this.f = c0536q;
        if (arrayList.size() > 1) {
            return;
        }
        throw new IllegalStateException(("MultiSelectionLayout requires an infoList size greater than 1, was " + arrayList.size() + '.').toString());
    }

    public static void n(androidx.collection.z zVar, C0536q c0536q, C0534o c0534o, int i, int i2) {
        C0536q c0536q2;
        if (c0536q.c) {
            c0536q2 = new C0536q(c0534o.a(i2), c0534o.a(i), i2 > i);
        } else {
            c0536q2 = new C0536q(c0534o.a(i), c0534o.a(i2), i > i2);
        }
        if (i > i2) {
            throw new IllegalStateException(("minOffset should be less than or equal to maxOffset: " + c0536q2).toString());
        }
        long j = c0534o.a;
        int iB = zVar.b(j);
        Object[] objArr = zVar.c;
        Object obj = objArr[iB];
        zVar.b[iB] = j;
        objArr[iB] = c0536q2;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int a() {
        return this.b.size();
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final boolean b() {
        return this.e;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o c() {
        return this.e ? l() : i();
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0536q d() {
        return this.f;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o e() {
        return j() == 1 ? i() : l();
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final androidx.collection.z f(C0536q c0536q) {
        C0535p c0535p = c0536q.a;
        long j = c0535p.c;
        C0535p c0535p2 = c0536q.b;
        long j2 = c0535p2.c;
        boolean z = c0536q.c;
        if (j != j2) {
            androidx.collection.z zVar = AbstractC0217o.a;
            androidx.collection.z zVar2 = new androidx.collection.z();
            C0535p c0535p3 = c0536q.a;
            n(zVar2, c0536q, e(), (z ? c0535p2 : c0535p3).b, e().f.a.a.a.length());
            k(new androidx.activity.compose.g(this, zVar2, c0536q, 14));
            if (z) {
                c0535p2 = c0535p3;
            }
            n(zVar2, c0536q, j() == 1 ? l() : i(), 0, c0535p2.b);
            return zVar2;
        }
        int i = c0535p.b;
        int i2 = c0535p2.b;
        if ((!z || i < i2) && (z || i > i2)) {
            throw new IllegalStateException(("unexpectedly miss-crossed selection: " + c0536q).toString());
        }
        androidx.collection.z zVar3 = AbstractC0217o.a;
        androidx.collection.z zVar4 = new androidx.collection.z();
        zVar4.f(j, c0536q);
        return zVar4;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final boolean g(I i) {
        if (this.f == null || i == null || !(i instanceof C0531l)) {
            return true;
        }
        C0531l c0531l = (C0531l) i;
        if (this.e != c0531l.e || this.c != c0531l.c || this.d != c0531l.d) {
            return true;
        }
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        ArrayList arrayList2 = c0531l.b;
        if (size != arrayList2.size()) {
            return true;
        }
        int size2 = arrayList.size();
        for (int i2 = 0; i2 < size2; i2++) {
            C0534o c0534o = (C0534o) arrayList.get(i2);
            C0534o c0534o2 = (C0534o) arrayList2.get(i2);
            c0534o.getClass();
            if (c0534o.a != c0534o2.a || c0534o.c != c0534o2.c || c0534o.d != c0534o2.d) {
                return true;
            }
        }
        return false;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int h() {
        return this.d;
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o i() {
        return (C0534o) this.b.get(p(this.d, false));
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int j() {
        int i = this.c;
        int i2 = this.d;
        if (i < i2) {
            return 2;
        }
        if (i > i2) {
            return 1;
        }
        return ((C0534o) this.b.get(i / 2)).b();
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final void k(Function1 function1) {
        int iO = o(e().a);
        int iO2 = o((j() == 1 ? l() : i()).a);
        int i = iO + 1;
        if (i >= iO2) {
            return;
        }
        while (i < iO2) {
            function1.invoke(this.b.get(i));
            i++;
        }
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final C0534o l() {
        return (C0534o) this.b.get(p(this.c, true));
    }

    @Override // androidx.compose.foundation.text.selection.I
    public final int m() {
        return this.c;
    }

    public final int o(long j) {
        try {
            return this.a.c(j);
        } catch (NoSuchElementException e) {
            throw new IllegalStateException(androidx.compose.animation.d0.n(j, "Invalid selectableId: "), e);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final int p(int i, boolean z) {
        int iK = AbstractC0147y.k(j());
        int i2 = z;
        if (iK == 0) {
            i2 = z == 0 ? 1 : 0;
        } else if (iK != 1) {
            if (iK != 2) {
                throw new NoWhenBranchMatchedException();
            }
        }
        return (i - (i2 ^ 1)) / 2;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MultiSelectionLayout(isStartHandle=");
        sb.append(this.e);
        sb.append(", startPosition=");
        boolean z = true;
        float f = 2;
        sb.append((this.c + 1) / f);
        sb.append(", endPosition=");
        sb.append((this.d + 1) / f);
        sb.append(", crossed=");
        sb.append(androidx.compose.animation.d0.z(j()));
        sb.append(", infos=");
        StringBuilder sb2 = new StringBuilder("[\n\t");
        ArrayList arrayList = this.b;
        int size = arrayList.size();
        int i = 0;
        while (i < size) {
            C0534o c0534o = (C0534o) arrayList.get(i);
            if (z) {
                z = false;
            } else {
                sb2.append(",\n\t");
            }
            StringBuilder sb3 = new StringBuilder();
            i++;
            sb3.append(i);
            sb3.append(" -> ");
            sb3.append(c0534o);
            sb2.append(sb3.toString());
        }
        sb2.append("\n]");
        String string = sb2.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        sb.append(string);
        sb.append(')');
        return sb.toString();
    }
}
