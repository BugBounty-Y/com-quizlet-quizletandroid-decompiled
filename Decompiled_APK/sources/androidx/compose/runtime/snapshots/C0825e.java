package androidx.compose.runtime.snapshots;

import androidx.collection.J;
import java.util.Arrays;
import java.util.HashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.snapshots.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0825e extends C0824d {
    public final C0824d o;
    public boolean p;

    public C0825e(long j, l lVar, Function1 function1, Function1 function12, C0824d c0824d) {
        super(j, lVar, function1, function12);
        this.o = c0824d;
        c0824d.k();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d, androidx.compose.runtime.snapshots.h
    public final void c() {
        if (this.c) {
            return;
        }
        super.c();
        if (this.p) {
            return;
        }
        this.p = true;
        this.o.l();
    }

    @Override // androidx.compose.runtime.snapshots.C0824d
    public final r w() throws Throwable {
        C0825e c0825e;
        C0824d c0824d = this.o;
        if (c0824d.m || c0824d.c) {
            return new i(this);
        }
        J elements = this.h;
        long j = this.b;
        HashMap mapC = elements != null ? m.c(c0824d.g(), this, this.o.d()) : null;
        Object obj = m.b;
        synchronized (obj) {
            try {
                m.d(this);
                try {
                    if (elements == null || elements.d == 0) {
                        c0825e = this;
                        a();
                    } else {
                        c0825e = this;
                        r rVarZ = c0825e.z(this.o.g(), elements, mapC, this.o.d());
                        if (!rVarZ.equals(j.c)) {
                            return rVarZ;
                        }
                        J jX = c0825e.o.x();
                        if (jX != null) {
                            Intrinsics.checkNotNullParameter(elements, "elements");
                            jX.i(elements);
                        } else {
                            c0825e.o.B(elements);
                            c0825e.h = null;
                        }
                    }
                    if (c0825e.o.g() < j) {
                        c0825e.o.v();
                    }
                    C0824d c0824d2 = c0825e.o;
                    c0824d2.r(c0824d2.d().b(j).a(c0825e.j));
                    c0825e.o.A(j);
                    C0824d c0824d3 = c0825e.o;
                    int i = c0825e.d;
                    c0825e.d = -1;
                    if (i >= 0) {
                        int[] iArr = c0824d3.k;
                        Intrinsics.checkNotNullParameter(iArr, "<this>");
                        int length = iArr.length;
                        int[] iArrCopyOf = Arrays.copyOf(iArr, length + 1);
                        iArrCopyOf[length] = i;
                        c0824d3.k = iArrCopyOf;
                    } else {
                        c0824d3.getClass();
                    }
                    C0824d c0824d4 = c0825e.o;
                    l lVar = c0825e.j;
                    c0824d4.getClass();
                    synchronized (obj) {
                        c0824d4.j = c0824d4.j.g(lVar);
                        Unit unit = Unit.a;
                        C0824d c0824d5 = c0825e.o;
                        int[] elements2 = c0825e.k;
                        c0824d5.getClass();
                        if (elements2.length != 0) {
                            int[] iArr2 = c0824d5.k;
                            if (iArr2.length != 0) {
                                Intrinsics.checkNotNullParameter(iArr2, "<this>");
                                Intrinsics.checkNotNullParameter(elements2, "elements");
                                int length2 = iArr2.length;
                                int length3 = elements2.length;
                                int[] iArrCopyOf2 = Arrays.copyOf(iArr2, length2 + length3);
                                System.arraycopy(elements2, 0, iArrCopyOf2, length2, length3);
                                Intrinsics.d(iArrCopyOf2);
                                elements2 = iArrCopyOf2;
                            }
                            c0824d5.k = elements2;
                        }
                    }
                    c0825e.m = true;
                    if (!c0825e.p) {
                        c0825e.p = true;
                        c0825e.o.l();
                    }
                    return j.c;
                } catch (Throwable th) {
                    th = th;
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
    }
}
