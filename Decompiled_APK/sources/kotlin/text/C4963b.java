package kotlin.text;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* renamed from: kotlin.text.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4963b implements Iterator, kotlin.jvm.internal.markers.a {
    public int a = -1;
    public int b;
    public int c;
    public IntRange d;
    public int e;
    public final /* synthetic */ C4964c f;

    public C4963b(C4964c c4964c) {
        this.f = c4964c;
        c4964c.getClass();
        int iC = kotlin.ranges.l.c(0, 0, c4964c.a.length());
        this.b = iC;
        this.c = iC;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x001c  */
    /* JADX WARN: Type inference failed for: r0v1, types: [kotlin.jvm.functions.Function2, kotlin.jvm.internal.r] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            r8 = this;
            int r0 = r8.c
            r1 = 0
            if (r0 >= 0) goto Lb
            r8.a = r1
            r0 = 0
            r8.d = r0
            return
        Lb:
            kotlin.text.c r2 = r8.f
            int r3 = r2.b
            java.lang.CharSequence r4 = r2.a
            r5 = -1
            r6 = 1
            if (r3 <= 0) goto L1c
            int r7 = r8.e
            int r7 = r7 + r6
            r8.e = r7
            if (r7 >= r3) goto L22
        L1c:
            int r3 = r4.length()
            if (r0 <= r3) goto L32
        L22:
            kotlin.ranges.IntRange r0 = new kotlin.ranges.IntRange
            int r1 = r8.b
            int r2 = kotlin.text.StringsKt.J(r4)
            r0.<init>(r1, r2, r6)
            r8.d = r0
            r8.c = r5
            goto L73
        L32:
            kotlin.jvm.internal.r r0 = r2.c
            int r2 = r8.c
            java.lang.Integer r2 = java.lang.Integer.valueOf(r2)
            java.lang.Object r0 = r0.invoke(r4, r2)
            kotlin.Pair r0 = (kotlin.Pair) r0
            if (r0 != 0) goto L52
            kotlin.ranges.IntRange r0 = new kotlin.ranges.IntRange
            int r1 = r8.b
            int r2 = kotlin.text.StringsKt.J(r4)
            r0.<init>(r1, r2, r6)
            r8.d = r0
            r8.c = r5
            goto L73
        L52:
            java.lang.Object r2 = r0.a
            java.lang.Number r2 = (java.lang.Number) r2
            int r2 = r2.intValue()
            java.lang.Object r0 = r0.b
            java.lang.Number r0 = (java.lang.Number) r0
            int r0 = r0.intValue()
            int r3 = r8.b
            kotlin.ranges.IntRange r3 = kotlin.ranges.l.h(r3, r2)
            r8.d = r3
            int r2 = r2 + r0
            r8.b = r2
            if (r0 != 0) goto L70
            r1 = r6
        L70:
            int r2 = r2 + r1
            r8.c = r2
        L73:
            r8.a = r6
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlin.text.C4963b.a():void");
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        if (this.a == -1) {
            a();
        }
        return this.a == 1;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (this.a == -1) {
            a();
        }
        if (this.a == 0) {
            throw new NoSuchElementException();
        }
        IntRange intRange = this.d;
        Intrinsics.e(intRange, "null cannot be cast to non-null type kotlin.ranges.IntRange");
        this.d = null;
        this.a = -1;
        return intRange;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException("Operation is not supported for read-only collection");
    }
}
