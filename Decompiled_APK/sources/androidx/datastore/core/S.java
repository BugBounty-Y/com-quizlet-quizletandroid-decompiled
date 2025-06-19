package androidx.datastore.core;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class S implements d0 {
    public final File a;
    public final f0 b;
    public final AtomicBoolean c;

    public S(File file, f0 serializer) {
        Intrinsics.checkNotNullParameter(file, "file");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.a = file;
        this.b = serializer;
        this.c = new AtomicBoolean(false);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r2v0, types: [int] */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v11, types: [androidx.datastore.core.S] */
    /* JADX WARN: Type inference failed for: r2v5 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object f(androidx.datastore.core.S r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            Method dump skipped, instructions count: 185
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.S.f(androidx.datastore.core.S, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.datastore.core.InterfaceC1069a
    public final void close() {
        this.c.set(true);
    }

    @Override // androidx.datastore.core.d0
    public final Object e(C1085q c1085q) {
        return f(this, c1085q);
    }
}
