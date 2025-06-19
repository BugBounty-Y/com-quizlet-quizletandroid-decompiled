package androidx.datastore.core;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class X implements n0 {
    public final File a;
    public final f0 b;
    public final k0 c;
    public final androidx.compose.ui.input.nestedscroll.b d;
    public final AtomicBoolean e;
    public final kotlinx.coroutines.sync.c f;

    public X(File file, f0 serializer, k0 coordinator, androidx.compose.ui.input.nestedscroll.b onClose) {
        Intrinsics.checkNotNullParameter(file, "file");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(coordinator, "coordinator");
        Intrinsics.checkNotNullParameter(onClose, "onClose");
        this.a = file;
        this.b = serializer;
        this.c = coordinator;
        this.d = onClose;
        this.e = new AtomicBoolean(false);
        this.f = kotlinx.coroutines.sync.d.a();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00e9 A[Catch: all -> 0x0119, IOException -> 0x011b, TRY_ENTER, TryCatch #4 {all -> 0x0119, blocks: (B:44:0x00e9, B:46:0x00ef, B:49:0x00f8, B:50:0x0118, B:55:0x011e, B:58:0x0128, B:67:0x0137, B:69:0x013d, B:70:0x0140, B:65:0x0135, B:64:0x0132, B:33:0x009e, B:34:0x00ba), top: B:83:0x009e }] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0128 A[Catch: all -> 0x0119, IOException -> 0x011b, TRY_ENTER, TRY_LEAVE, TryCatch #4 {all -> 0x0119, blocks: (B:44:0x00e9, B:46:0x00ef, B:49:0x00f8, B:50:0x0118, B:55:0x011e, B:58:0x0128, B:67:0x0137, B:69:0x013d, B:70:0x0140, B:65:0x0135, B:64:0x0132, B:33:0x009e, B:34:0x00ba), top: B:83:0x009e }] */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0015  */
    @Override // androidx.datastore.core.n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object a(androidx.datastore.core.O r12, kotlin.coroutines.jvm.internal.c r13) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 335
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.X.a(androidx.datastore.core.O, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.datastore.core.n0
    public final k0 c() {
        return this.c;
    }

    @Override // androidx.datastore.core.InterfaceC1069a
    public final void close() {
        this.e.set(true);
        this.d.invoke();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x007a A[Catch: all -> 0x007b, TRY_ENTER, TRY_LEAVE, TryCatch #1 {all -> 0x007b, blocks: (B:33:0x007a, B:42:0x008b, B:41:0x0088, B:38:0x0083), top: B:52:0x0020, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v11 */
    /* JADX WARN: Type inference failed for: r0v13, types: [androidx.datastore.core.X] */
    /* JADX WARN: Type inference failed for: r0v16 */
    /* JADX WARN: Type inference failed for: r0v17 */
    /* JADX WARN: Type inference failed for: r0v2, types: [androidx.datastore.core.V, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r0v3 */
    /* JADX WARN: Type inference failed for: r0v4, types: [androidx.datastore.core.X] */
    /* JADX WARN: Type inference failed for: r0v6 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r8v0, types: [androidx.datastore.core.q] */
    /* JADX WARN: Type inference failed for: r8v1 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v15, types: [boolean] */
    /* JADX WARN: Type inference failed for: r8v2 */
    /* JADX WARN: Type inference failed for: r8v6 */
    /* JADX WARN: Type inference failed for: r8v8 */
    @Override // androidx.datastore.core.n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(androidx.datastore.core.C1085q r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r9 instanceof androidx.datastore.core.V
            if (r0 == 0) goto L13
            r0 = r9
            androidx.datastore.core.V r0 = (androidx.datastore.core.V) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.datastore.core.V r0 = new androidx.datastore.core.V
            r0.<init>(r7, r9)
        L18:
            java.lang.Object r9 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 != r4) goto L30
            boolean r8 = r0.l
            androidx.datastore.core.S r1 = r0.k
            androidx.datastore.core.X r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L2e
            goto L6a
        L2e:
            r9 = move-exception
            goto L83
        L30:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.util.concurrent.atomic.AtomicBoolean r9 = r7.e
            boolean r9 = r9.get()
            if (r9 != 0) goto L99
            kotlinx.coroutines.sync.c r9 = r7.f
            boolean r9 = r9.e()
            androidx.datastore.core.S r2 = new androidx.datastore.core.S     // Catch: java.lang.Throwable -> L8c
            java.io.File r5 = r7.a     // Catch: java.lang.Throwable -> L8c
            androidx.datastore.core.f0 r6 = r7.b     // Catch: java.lang.Throwable -> L8c
            r2.<init>(r5, r6)     // Catch: java.lang.Throwable -> L8c
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r9)     // Catch: java.lang.Throwable -> L7d
            r0.j = r7     // Catch: java.lang.Throwable -> L7d
            r0.k = r2     // Catch: java.lang.Throwable -> L7d
            r0.l = r9     // Catch: java.lang.Throwable -> L7d
            r0.o = r4     // Catch: java.lang.Throwable -> L7d
            java.lang.Object r8 = r8.invoke(r2, r5, r0)     // Catch: java.lang.Throwable -> L7d
            if (r8 != r1) goto L65
            return r1
        L65:
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r7
            r1 = r2
        L6a:
            r1.close()     // Catch: java.lang.Throwable -> L6f
            r1 = r3
            goto L70
        L6f:
            r1 = move-exception
        L70:
            if (r1 != 0) goto L7a
            if (r8 == 0) goto L79
            kotlinx.coroutines.sync.c r8 = r0.f
            r8.f(r3)
        L79:
            return r9
        L7a:
            throw r1     // Catch: java.lang.Throwable -> L7b
        L7b:
            r9 = move-exception
            goto L91
        L7d:
            r8 = move-exception
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r7
            r1 = r2
        L83:
            r1.close()     // Catch: java.lang.Throwable -> L87
            goto L8b
        L87:
            r1 = move-exception
            kotlin.C4937f.a(r9, r1)     // Catch: java.lang.Throwable -> L7b
        L8b:
            throw r9     // Catch: java.lang.Throwable -> L7b
        L8c:
            r8 = move-exception
            r0 = r9
            r9 = r8
            r8 = r0
            r0 = r7
        L91:
            if (r8 == 0) goto L98
            kotlinx.coroutines.sync.c r8 = r0.f
            r8.f(r3)
        L98:
            throw r9
        L99:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "StorageConnection has already been disposed."
            r8.<init>(r9)
            throw r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.X.d(androidx.datastore.core.q, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
