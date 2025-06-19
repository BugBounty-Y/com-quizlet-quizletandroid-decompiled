package com.quizlet.shared.repository.folderstudymaterials;

import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.shared.cache.a {
    public final /* synthetic */ int a = 1;
    public final com.quizlet.shared.cache.a b;

    public a(com.quizlet.shared.cache.a cache) {
        Intrinsics.checkNotNullParameter(cache, "cache");
        Intrinsics.checkNotNullParameter(cache, "cache");
        this.b = cache;
    }

    /* JADX WARN: Code restructure failed: missing block: B:17:0x004a, code lost:
    
        if (r6 == r1) goto L24;
     */
    /* JADX WARN: Removed duplicated region for block: B:22:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object d(com.quizlet.shared.repository.folderstudymaterials.a r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof com.quizlet.shared.cache.v
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.shared.cache.v r0 = (com.quizlet.shared.cache.v) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.shared.cache.v r0 = new com.quizlet.shared.cache.v
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3c
            if (r2 == r4) goto L36
            if (r2 != r3) goto L2e
            java.util.Iterator r5 = r0.k
            com.quizlet.shared.repository.folderstudymaterials.a r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L55
        L2e:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L36:
            com.quizlet.shared.repository.folderstudymaterials.a r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4d
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.n = r4
            r5.getClass()
            java.lang.Object r6 = e(r5, r0)
            if (r6 != r1) goto L4d
            goto L6d
        L4d:
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            java.util.Iterator r6 = r6.iterator()
            r2 = r5
            r5 = r6
        L55:
            boolean r6 = r5.hasNext()
            if (r6 == 0) goto L6e
            java.lang.Object r6 = r5.next()
            serialization.e r6 = (serialization.e) r6
            r0.j = r2
            r0.k = r5
            r0.n = r3
            java.lang.Object r6 = r2.f(r6, r0)
            if (r6 != r1) goto L55
        L6d:
            return r1
        L6e:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.repository.folderstudymaterials.a.d(com.quizlet.shared.repository.folderstudymaterials.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object e(com.quizlet.shared.repository.folderstudymaterials.a r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof com.quizlet.shared.cache.w
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.shared.cache.w r0 = (com.quizlet.shared.cache.w) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.shared.cache.w r0 = new com.quizlet.shared.cache.w
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3d
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.shared.cache.a r4 = r4.b
            r0.l = r3
            java.lang.Object r5 = r4.a(r0)
            if (r5 != r1) goto L3d
            return r1
        L3d:
            java.lang.Iterable r5 = (java.lang.Iterable) r5
            java.util.ArrayList r4 = new java.util.ArrayList
            r4.<init>()
            java.util.Iterator r5 = r5.iterator()
        L48:
            boolean r0 = r5.hasNext()
            if (r0 == 0) goto L5e
            java.lang.Object r0 = r5.next()
            serialization.e r0 = (serialization.e) r0
            if (r0 == 0) goto L57
            goto L58
        L57:
            r0 = 0
        L58:
            if (r0 == 0) goto L48
            r4.add(r0)
            goto L48
        L5e:
            java.util.Set r4 = kotlin.collections.CollectionsKt.A0(r4)
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.repository.folderstudymaterials.a.e(com.quizlet.shared.repository.folderstudymaterials.a, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    @Override // com.quizlet.shared.cache.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            int r0 = r4.a
            switch(r0) {
                case 0: goto L6d;
                default: goto L5;
            }
        L5:
            boolean r0 = r5 instanceof com.quizlet.shared.cache.e
            if (r0 == 0) goto L18
            r0 = r5
            com.quizlet.shared.cache.e r0 = (com.quizlet.shared.cache.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L18
            int r1 = r1 - r2
            r0.l = r1
            goto L1d
        L18:
            com.quizlet.shared.cache.e r0 = new com.quizlet.shared.cache.e
            r0.<init>(r4, r5)
        L1d:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L34
            if (r2 != r3) goto L2c
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L42
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            com.quizlet.shared.cache.a r5 = r4.b
            java.lang.Object r5 = r5.a(r0)
            if (r5 != r1) goto L42
            goto L6c
        L42:
            java.lang.Iterable r5 = (java.lang.Iterable) r5
            java.util.ArrayList r0 = new java.util.ArrayList
            r1 = 10
            int r1 = kotlin.collections.C.q(r5, r1)
            r0.<init>(r1)
            java.util.Iterator r5 = r5.iterator()
        L53:
            boolean r1 = r5.hasNext()
            if (r1 == 0) goto L68
            java.lang.Object r1 = r5.next()
            serialization.e r1 = (serialization.e) r1
            com.quizlet.shared.cache.f r2 = new com.quizlet.shared.cache.f
            r2.<init>(r1)
            r0.add(r2)
            goto L53
        L68:
            java.util.Set r1 = kotlin.collections.CollectionsKt.A0(r0)
        L6c:
            return r1
        L6d:
            java.lang.Object r5 = e(r4, r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.repository.folderstudymaterials.a.a(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.shared.cache.a
    public final Object b(Object obj, kotlin.coroutines.jvm.internal.c cVar) {
        switch (this.a) {
            case 0:
                return f((serialization.e) obj, cVar);
            default:
                Object objB = this.b.b(((com.quizlet.shared.cache.f) obj).a, cVar);
                return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
        }
    }

    @Override // com.quizlet.shared.cache.a
    public final Object c(kotlin.coroutines.jvm.internal.c cVar) {
        switch (this.a) {
            case 0:
                return d(this, cVar);
            default:
                Object objC = this.b.c(cVar);
                return objC == kotlin.coroutines.intrinsics.a.a ? objC : Unit.a;
        }
    }

    public Object f(serialization.e eVar, h hVar) {
        Object objB = this.b.b(eVar, (kotlin.coroutines.jvm.internal.c) hVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    public a(com.quizlet.quizletandroid.logging.initializer.a getTimeInMillisecondsUseCase, com.quizlet.shared.cache.a delegate) {
        Intrinsics.checkNotNullParameter(getTimeInMillisecondsUseCase, "getTimeInMillisecondsUseCase");
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
    }
}
