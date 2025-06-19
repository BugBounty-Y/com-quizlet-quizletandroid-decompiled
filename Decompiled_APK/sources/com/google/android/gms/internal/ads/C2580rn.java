package com.google.android.gms.internal.ads;

import android.content.Context;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.rn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2580rn {
    public static C2580rn f;
    public boolean a;
    public int b;
    public final Object c;
    public final Object d;
    public Object e;

    public C2580rn(Context context) {
        Executor executorD = AbstractC1972di.d();
        this.c = executorD;
        this.d = new CopyOnWriteArrayList();
        this.e = new Object();
        this.b = 0;
        executorD.execute(new RunnableC2793wl(1, this, context));
    }

    public static synchronized C2580rn d(Context context) {
        try {
            if (f == null) {
                f = new C2580rn(context);
            }
        } catch (Throwable th) {
            throw th;
        }
        return f;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object a(kotlinx.coroutines.InterfaceC5025j0 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof androidx.paging.c1
            if (r0 == 0) goto L13
            r0 = r6
            androidx.paging.c1 r0 = (androidx.paging.c1) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.paging.c1 r0 = new androidx.paging.c1
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L37
            if (r2 != r3) goto L2f
            kotlinx.coroutines.sync.c r5 = r0.l
            kotlinx.coroutines.j0 r1 = r0.k
            com.google.android.gms.internal.ads.rn r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r6 = r5
            r5 = r1
            goto L4e
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r4
            r0.k = r5
            java.lang.Object r6 = r4.d
            kotlinx.coroutines.sync.c r6 = (kotlinx.coroutines.sync.c) r6
            r0.l = r6
            r0.o = r3
            java.lang.Object r0 = r6.d(r0)
            if (r0 != r1) goto L4d
            return r1
        L4d:
            r0 = r4
        L4e:
            r1 = 0
            java.lang.Object r2 = r0.e     // Catch: java.lang.Throwable -> L58
            kotlinx.coroutines.j0 r2 = (kotlinx.coroutines.InterfaceC5025j0) r2     // Catch: java.lang.Throwable -> L58
            if (r5 != r2) goto L5a
            r0.e = r1     // Catch: java.lang.Throwable -> L58
            goto L5a
        L58:
            r5 = move-exception
            goto L62
        L5a:
            kotlin.Unit r5 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L58
            r6.f(r1)
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        L62:
            r6.f(r1)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2580rn.a(kotlinx.coroutines.j0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r11v0, types: [kotlinx.coroutines.j0] */
    /* JADX WARN: Type inference failed for: r11v1 */
    /* JADX WARN: Type inference failed for: r11v11, types: [kotlinx.coroutines.sync.a] */
    /* JADX WARN: Type inference failed for: r11v14 */
    /* JADX WARN: Type inference failed for: r11v15 */
    /* JADX WARN: Type inference failed for: r11v5 */
    /* JADX WARN: Type inference failed for: r11v9, types: [kotlinx.coroutines.sync.a] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(int r10, kotlinx.coroutines.InterfaceC5025j0 r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r9 = this;
            boolean r0 = r12 instanceof androidx.paging.d1
            if (r0 == 0) goto L13
            r0 = r12
            androidx.paging.d1 r0 = (androidx.paging.d1) r0
            int r1 = r0.p
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.p = r1
            goto L18
        L13:
            androidx.paging.d1 r0 = new androidx.paging.d1
            r0.<init>(r9, r12)
        L18:
            java.lang.Object r12 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.p
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L4b
            if (r2 == r4) goto L3f
            if (r2 != r3) goto L37
            int r10 = r0.m
            kotlinx.coroutines.sync.a r11 = r0.l
            kotlinx.coroutines.j0 r1 = r0.k
            com.google.android.gms.internal.ads.rn r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)     // Catch: java.lang.Throwable -> L34
            goto La2
        L34:
            r10 = move-exception
            goto Lb2
        L37:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L3f:
            int r10 = r0.m
            kotlinx.coroutines.sync.a r11 = r0.l
            kotlinx.coroutines.j0 r2 = r0.k
            com.google.android.gms.internal.ads.rn r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L66
        L4b:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            r0.j = r9
            r0.k = r11
            java.lang.Object r12 = r9.d
            kotlinx.coroutines.sync.c r12 = (kotlinx.coroutines.sync.c) r12
            r0.l = r12
            r0.m = r10
            r0.p = r4
            java.lang.Object r2 = r12.d(r0)
            if (r2 != r1) goto L63
            goto L9f
        L63:
            r6 = r9
            r2 = r11
            r11 = r12
        L66:
            java.lang.Object r12 = r6.e     // Catch: java.lang.Throwable -> L34
            kotlinx.coroutines.j0 r12 = (kotlinx.coroutines.InterfaceC5025j0) r12     // Catch: java.lang.Throwable -> L34
            if (r12 == 0) goto L7f
            boolean r7 = r12.a()     // Catch: java.lang.Throwable -> L34
            if (r7 == 0) goto L7f
            int r7 = r6.b     // Catch: java.lang.Throwable -> L34
            if (r7 < r10) goto L7f
            if (r7 != r10) goto L7d
            boolean r7 = r6.a     // Catch: java.lang.Throwable -> L34
            if (r7 == 0) goto L7d
            goto L7f
        L7d:
            r4 = 0
            goto La8
        L7f:
            if (r12 == 0) goto L8d
            androidx.paging.b1 r7 = new androidx.paging.b1     // Catch: java.lang.Throwable -> L34
            java.lang.Object r8 = r6.c     // Catch: java.lang.Throwable -> L34
            androidx.appcompat.app.L r8 = (androidx.appcompat.app.L) r8     // Catch: java.lang.Throwable -> L34
            r7.<init>(r8)     // Catch: java.lang.Throwable -> L34
            r12.j(r7)     // Catch: java.lang.Throwable -> L34
        L8d:
            if (r12 == 0) goto La4
            r0.j = r6     // Catch: java.lang.Throwable -> L34
            r0.k = r2     // Catch: java.lang.Throwable -> L34
            r0.l = r11     // Catch: java.lang.Throwable -> L34
            r0.m = r10     // Catch: java.lang.Throwable -> L34
            r0.p = r3     // Catch: java.lang.Throwable -> L34
            java.lang.Object r12 = r12.p(r0)     // Catch: java.lang.Throwable -> L34
            if (r12 != r1) goto La0
        L9f:
            return r1
        La0:
            r1 = r2
            r0 = r6
        La2:
            r6 = r0
            r2 = r1
        La4:
            r6.e = r2     // Catch: java.lang.Throwable -> L34
            r6.b = r10     // Catch: java.lang.Throwable -> L34
        La8:
            java.lang.Boolean r10 = java.lang.Boolean.valueOf(r4)     // Catch: java.lang.Throwable -> L34
            kotlinx.coroutines.sync.c r11 = (kotlinx.coroutines.sync.c) r11
            r11.f(r5)
            return r10
        Lb2:
            kotlinx.coroutines.sync.c r11 = (kotlinx.coroutines.sync.c) r11
            r11.f(r5)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2580rn.b(int, kotlinx.coroutines.j0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public int c() {
        int i;
        synchronized (this.e) {
            i = this.b;
        }
        return i;
    }

    public void e(int i) {
        CopyOnWriteArrayList copyOnWriteArrayList = (CopyOnWriteArrayList) this.d;
        Iterator it2 = copyOnWriteArrayList.iterator();
        while (it2.hasNext()) {
            Jm jm = (Jm) it2.next();
            if (jm.a.get() == null) {
                copyOnWriteArrayList.remove(jm);
            }
        }
        synchronized (this.e) {
            try {
                if (this.a && this.b == i) {
                    return;
                }
                this.a = true;
                this.b = i;
                Iterator it3 = ((CopyOnWriteArrayList) this.d).iterator();
                while (it3.hasNext()) {
                    Jm jm2 = (Jm) it3.next();
                    jm2.getClass();
                    jm2.b.execute(new RunnableC2104gj(jm2, 6));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public C2580rn(androidx.appcompat.app.L singleRunner, boolean z) {
        Intrinsics.checkNotNullParameter(singleRunner, "singleRunner");
        this.c = singleRunner;
        this.a = z;
        this.d = kotlinx.coroutines.sync.d.a();
    }
}
