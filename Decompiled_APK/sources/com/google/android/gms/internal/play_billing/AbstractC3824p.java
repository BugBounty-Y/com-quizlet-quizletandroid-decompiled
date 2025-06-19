package com.google.android.gms.internal.play_billing;

import java.util.Iterator;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

/* renamed from: com.google.android.gms.internal.play_billing.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3824p {
    public static final Collector a;

    static {
        final int i = 0;
        final int i2 = 0;
        final int i3 = 1;
        final int i4 = 1;
        a = Collector.of(new Supplier() { // from class: com.google.android.gms.internal.play_billing.l
            @Override // java.util.function.Supplier
            public final Object get() {
                switch (i) {
                    case 0:
                        return new C3847x(1, (byte) 0);
                    case 1:
                        return new F(1, (byte) 0);
                    default:
                        return new D();
                }
            }
        }, new BiConsumer() { // from class: com.google.android.gms.internal.play_billing.o
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i2) {
                    case 0:
                        ((C3847x) obj).c(obj2);
                        return;
                    case 1:
                        F f = (F) obj;
                        f.getClass();
                        obj2.getClass();
                        f.c(obj2);
                        return;
                    default:
                        D d = (D) obj;
                        O o = (O) obj2;
                        d.getClass();
                        if (o.a.equals(o.b)) {
                            throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                        }
                        d.a.add(o);
                        return;
                }
            }
        }, new BinaryOperator() { // from class: com.google.android.gms.internal.play_billing.m
            @Override // java.util.function.BiFunction
            public final Object apply(Object obj, Object obj2) {
                switch (i3) {
                    case 0:
                        D d = (D) obj;
                        d.getClass();
                        Iterator it2 = ((D) obj2).a.iterator();
                        while (it2.hasNext()) {
                            O o = (O) it2.next();
                            if (o.a.equals(o.b)) {
                                throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                            }
                            d.a.add(o);
                        }
                        return d;
                    case 1:
                        C3847x c3847x = (C3847x) obj;
                        C3847x c3847x2 = (C3847x) obj2;
                        Object[] objArr = c3847x2.b;
                        int i5 = c3847x2.c;
                        for (int i6 = 0; i6 < i5; i6++) {
                            c3847x.getClass();
                            if (objArr[i6] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i6, "at index "));
                            }
                        }
                        c3847x.g(i5);
                        System.arraycopy(objArr, 0, c3847x.b, c3847x.c, i5);
                        c3847x.c += i5;
                        return c3847x;
                    default:
                        F f = (F) obj;
                        F f2 = (F) obj2;
                        Object[] objArr2 = f2.b;
                        int i7 = f2.c;
                        for (int i8 = 0; i8 < i7; i8++) {
                            f.getClass();
                            if (objArr2[i8] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i8, "at index "));
                            }
                        }
                        f.g(i7);
                        System.arraycopy(objArr2, 0, f.b, f.c, i7);
                        f.c += i7;
                        return f;
                }
            }
        }, new Function() { // from class: com.google.android.gms.internal.play_billing.n
            /* JADX WARN: Removed duplicated region for block: B:102:0x0136 A[SYNTHETIC] */
            /* JADX WARN: Removed duplicated region for block: B:72:0x0132  */
            @Override // java.util.function.Function
            /*
                Code decompiled incorrectly, please refer to instructions dump.
                To view partially-correct add '--show-bad-code' argument
            */
            public final java.lang.Object apply(java.lang.Object r13) {
                /*
                    Method dump skipped, instructions count: 436
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3818n.apply(java.lang.Object):java.lang.Object");
            }
        }, new Collector.Characteristics[0]);
        final int i5 = 1;
        final int i6 = 1;
        final int i7 = 2;
        final int i8 = 2;
        Collector.of(new Supplier() { // from class: com.google.android.gms.internal.play_billing.l
            @Override // java.util.function.Supplier
            public final Object get() {
                switch (i5) {
                    case 0:
                        return new C3847x(1, (byte) 0);
                    case 1:
                        return new F(1, (byte) 0);
                    default:
                        return new D();
                }
            }
        }, new BiConsumer() { // from class: com.google.android.gms.internal.play_billing.o
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i6) {
                    case 0:
                        ((C3847x) obj).c(obj2);
                        return;
                    case 1:
                        F f = (F) obj;
                        f.getClass();
                        obj2.getClass();
                        f.c(obj2);
                        return;
                    default:
                        D d = (D) obj;
                        O o = (O) obj2;
                        d.getClass();
                        if (o.a.equals(o.b)) {
                            throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                        }
                        d.a.add(o);
                        return;
                }
            }
        }, new BinaryOperator() { // from class: com.google.android.gms.internal.play_billing.m
            @Override // java.util.function.BiFunction
            public final Object apply(Object obj, Object obj2) {
                switch (i7) {
                    case 0:
                        D d = (D) obj;
                        d.getClass();
                        Iterator it2 = ((D) obj2).a.iterator();
                        while (it2.hasNext()) {
                            O o = (O) it2.next();
                            if (o.a.equals(o.b)) {
                                throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                            }
                            d.a.add(o);
                        }
                        return d;
                    case 1:
                        C3847x c3847x = (C3847x) obj;
                        C3847x c3847x2 = (C3847x) obj2;
                        Object[] objArr = c3847x2.b;
                        int i52 = c3847x2.c;
                        for (int i62 = 0; i62 < i52; i62++) {
                            c3847x.getClass();
                            if (objArr[i62] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i62, "at index "));
                            }
                        }
                        c3847x.g(i52);
                        System.arraycopy(objArr, 0, c3847x.b, c3847x.c, i52);
                        c3847x.c += i52;
                        return c3847x;
                    default:
                        F f = (F) obj;
                        F f2 = (F) obj2;
                        Object[] objArr2 = f2.b;
                        int i72 = f2.c;
                        for (int i82 = 0; i82 < i72; i82++) {
                            f.getClass();
                            if (objArr2[i82] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i82, "at index "));
                            }
                        }
                        f.g(i72);
                        System.arraycopy(objArr2, 0, f.b, f.c, i72);
                        f.c += i72;
                        return f;
                }
            }
        }, new Function() { // from class: com.google.android.gms.internal.play_billing.n
            @Override // java.util.function.Function
            public final Object apply(Object v) {
                /*
                    Method dump skipped, instructions count: 436
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3818n.apply(java.lang.Object):java.lang.Object");
            }
        }, new Collector.Characteristics[0]);
        final int i9 = 2;
        final int i10 = 2;
        final int i11 = 0;
        final int i12 = 0;
        Collector.of(new Supplier() { // from class: com.google.android.gms.internal.play_billing.l
            @Override // java.util.function.Supplier
            public final Object get() {
                switch (i9) {
                    case 0:
                        return new C3847x(1, (byte) 0);
                    case 1:
                        return new F(1, (byte) 0);
                    default:
                        return new D();
                }
            }
        }, new BiConsumer() { // from class: com.google.android.gms.internal.play_billing.o
            @Override // java.util.function.BiConsumer
            public final void accept(Object obj, Object obj2) {
                switch (i10) {
                    case 0:
                        ((C3847x) obj).c(obj2);
                        return;
                    case 1:
                        F f = (F) obj;
                        f.getClass();
                        obj2.getClass();
                        f.c(obj2);
                        return;
                    default:
                        D d = (D) obj;
                        O o = (O) obj2;
                        d.getClass();
                        if (o.a.equals(o.b)) {
                            throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                        }
                        d.a.add(o);
                        return;
                }
            }
        }, new BinaryOperator() { // from class: com.google.android.gms.internal.play_billing.m
            @Override // java.util.function.BiFunction
            public final Object apply(Object obj, Object obj2) {
                switch (i11) {
                    case 0:
                        D d = (D) obj;
                        d.getClass();
                        Iterator it2 = ((D) obj2).a.iterator();
                        while (it2.hasNext()) {
                            O o = (O) it2.next();
                            if (o.a.equals(o.b)) {
                                throw new IllegalArgumentException(Z0.g("range must not be empty, but was %s", o));
                            }
                            d.a.add(o);
                        }
                        return d;
                    case 1:
                        C3847x c3847x = (C3847x) obj;
                        C3847x c3847x2 = (C3847x) obj2;
                        Object[] objArr = c3847x2.b;
                        int i52 = c3847x2.c;
                        for (int i62 = 0; i62 < i52; i62++) {
                            c3847x.getClass();
                            if (objArr[i62] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i62, "at index "));
                            }
                        }
                        c3847x.g(i52);
                        System.arraycopy(objArr, 0, c3847x.b, c3847x.c, i52);
                        c3847x.c += i52;
                        return c3847x;
                    default:
                        F f = (F) obj;
                        F f2 = (F) obj2;
                        Object[] objArr2 = f2.b;
                        int i72 = f2.c;
                        for (int i82 = 0; i82 < i72; i82++) {
                            f.getClass();
                            if (objArr2[i82] == null) {
                                throw new NullPointerException(android.support.v4.media.session.a.f(i82, "at index "));
                            }
                        }
                        f.g(i72);
                        System.arraycopy(objArr2, 0, f.b, f.c, i72);
                        f.c += i72;
                        return f;
                }
            }
        }, new Function() { // from class: com.google.android.gms.internal.play_billing.n
            @Override // java.util.function.Function
            public final Object apply(Object v) {
                /*
                    Method dump skipped, instructions count: 436
                    To view this dump add '--comments-level debug' option
                */
                throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.play_billing.C3818n.apply(java.lang.Object):java.lang.Object");
            }
        }, new Collector.Characteristics[0]);
    }
}
