package androidx.datastore.core.okio;

import androidx.datastore.core.k0;
import androidx.datastore.core.n0;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import okio.t;
import okio.x;

/* loaded from: classes.dex */
public final class h implements n0 {
    public final t a;
    public final x b;
    public final com.quizlet.data.repository.school.membership.a c;
    public final k0 d;
    public final d e;
    public final com.airbnb.lottie.network.d f;
    public final kotlinx.coroutines.sync.c g;

    public h(t fileSystem, x path, com.quizlet.data.repository.school.membership.a serializer, k0 coordinator, d onClose) {
        Intrinsics.checkNotNullParameter(fileSystem, "fileSystem");
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(coordinator, "coordinator");
        Intrinsics.checkNotNullParameter(onClose, "onClose");
        this.a = fileSystem;
        this.b = path;
        this.c = serializer;
        this.d = coordinator;
        this.e = onClose;
        this.f = new com.airbnb.lottie.network.d(13);
        this.g = kotlinx.coroutines.sync.d.a();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00cf A[Catch: all -> 0x00df, IOException -> 0x00e2, TRY_ENTER, TryCatch #2 {IOException -> 0x00e2, blocks: (B:42:0x00cf, B:44:0x00d7, B:53:0x00f0, B:60:0x00fe, B:59:0x00fb), top: B:79:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00f0 A[Catch: all -> 0x00df, IOException -> 0x00e2, TRY_ENTER, TRY_LEAVE, TryCatch #2 {IOException -> 0x00e2, blocks: (B:42:0x00cf, B:44:0x00d7, B:53:0x00f0, B:60:0x00fe, B:59:0x00fb), top: B:79:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    /* JADX WARN: Type inference failed for: r0v0, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, okio.x] */
    @Override // androidx.datastore.core.n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.datastore.core.O r11, kotlin.coroutines.jvm.internal.c r12) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.okio.h.a(androidx.datastore.core.O, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.datastore.core.n0
    public final k0 c() {
        return this.d;
    }

    @Override // androidx.datastore.core.InterfaceC1069a
    public final void close() {
        ((AtomicBoolean) this.f.b).set(true);
        this.e.invoke();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0080 A[Catch: all -> 0x0081, TRY_ENTER, TRY_LEAVE, TryCatch #0 {all -> 0x0081, blocks: (B:33:0x0080, B:42:0x0091, B:41:0x008e, B:38:0x0089), top: B:51:0x0020, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v13, types: [androidx.datastore.core.okio.h] */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v17 */
    /* JADX WARN: Type inference failed for: r0v2, types: [androidx.datastore.core.okio.f, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r0v3 */
    /* JADX WARN: Type inference failed for: r0v4, types: [androidx.datastore.core.okio.h] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r9v0, types: [androidx.datastore.core.q] */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v15, types: [boolean] */
    /* JADX WARN: Type inference failed for: r9v2 */
    /* JADX WARN: Type inference failed for: r9v6 */
    /* JADX WARN: Type inference failed for: r9v8 */
    @Override // androidx.datastore.core.n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(androidx.datastore.core.C1085q r9, kotlin.coroutines.jvm.internal.c r10) throws java.lang.Throwable {
        /*
            r8 = this;
            boolean r0 = r10 instanceof androidx.datastore.core.okio.f
            if (r0 == 0) goto L13
            r0 = r10
            androidx.datastore.core.okio.f r0 = (androidx.datastore.core.okio.f) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.datastore.core.okio.f r0 = new androidx.datastore.core.okio.f
            r0.<init>(r8, r10)
        L18:
            java.lang.Object r10 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 != r4) goto L30
            boolean r9 = r0.l
            androidx.datastore.core.okio.b r1 = r0.k
            androidx.datastore.core.okio.h r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)     // Catch: java.lang.Throwable -> L2e
            goto L70
        L2e:
            r10 = move-exception
            goto L89
        L30:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            com.airbnb.lottie.network.d r10 = r8.f
            java.lang.Object r10 = r10.b
            java.util.concurrent.atomic.AtomicBoolean r10 = (java.util.concurrent.atomic.AtomicBoolean) r10
            boolean r10 = r10.get()
            if (r10 != 0) goto La1
            kotlinx.coroutines.sync.c r10 = r8.g
            boolean r10 = r10.e()
            androidx.datastore.core.okio.b r2 = new androidx.datastore.core.okio.b     // Catch: java.lang.Throwable -> L97
            okio.t r5 = r8.a     // Catch: java.lang.Throwable -> L97
            okio.x r6 = r8.b     // Catch: java.lang.Throwable -> L97
            com.quizlet.data.repository.school.membership.a r7 = r8.c     // Catch: java.lang.Throwable -> L97
            r2.<init>(r5, r6, r7)     // Catch: java.lang.Throwable -> L97
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r10)     // Catch: java.lang.Throwable -> L83
            r0.j = r8     // Catch: java.lang.Throwable -> L83
            r0.k = r2     // Catch: java.lang.Throwable -> L83
            r0.l = r10     // Catch: java.lang.Throwable -> L83
            r0.o = r4     // Catch: java.lang.Throwable -> L83
            java.lang.Object r9 = r9.invoke(r2, r5, r0)     // Catch: java.lang.Throwable -> L83
            if (r9 != r1) goto L6b
            return r1
        L6b:
            r0 = r10
            r10 = r9
            r9 = r0
            r0 = r8
            r1 = r2
        L70:
            r1.close()     // Catch: java.lang.Throwable -> L75
            r1 = r3
            goto L76
        L75:
            r1 = move-exception
        L76:
            if (r1 != 0) goto L80
            if (r9 == 0) goto L7f
            kotlinx.coroutines.sync.c r9 = r0.g
            r9.f(r3)
        L7f:
            return r10
        L80:
            throw r1     // Catch: java.lang.Throwable -> L81
        L81:
            r10 = move-exception
            goto L99
        L83:
            r9 = move-exception
            r0 = r10
            r10 = r9
            r9 = r0
            r0 = r8
            r1 = r2
        L89:
            r1.close()     // Catch: java.lang.Throwable -> L8d
            goto L91
        L8d:
            r1 = move-exception
            kotlin.C4937f.a(r10, r1)     // Catch: java.lang.Throwable -> L81
        L91:
            throw r10     // Catch: java.lang.Throwable -> L81
        L92:
            r0 = r10
            r10 = r9
            r9 = r0
            r0 = r8
            goto L99
        L97:
            r9 = move-exception
            goto L92
        L99:
            if (r9 == 0) goto La0
            kotlinx.coroutines.sync.c r9 = r0.g
            r9.f(r3)
        La0:
            throw r10
        La1:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "StorageConnection has already been disposed."
            r9.<init>(r10)
            throw r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.okio.h.d(androidx.datastore.core.q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
