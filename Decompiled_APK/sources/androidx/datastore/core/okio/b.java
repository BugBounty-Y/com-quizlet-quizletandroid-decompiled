package androidx.datastore.core.okio;

import androidx.datastore.core.C1085q;
import androidx.datastore.core.d0;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import okio.t;
import okio.x;

/* loaded from: classes.dex */
public class b implements d0 {
    public final t a;
    public final x b;
    public final com.quizlet.data.repository.school.membership.a c;
    public final com.airbnb.lottie.network.d d;

    public b(t fileSystem, x path, com.quizlet.data.repository.school.membership.a serializer) {
        Intrinsics.checkNotNullParameter(fileSystem, "fileSystem");
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.a = fileSystem;
        this.b = path;
        this.c = serializer;
        this.d = new com.airbnb.lottie.network.d(13);
    }

    /* JADX WARN: Code restructure failed: missing block: B:54:0x00d1, code lost:
    
        if (r9 == r1) goto L55;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00a2 A[Catch: FileNotFoundException -> 0x009c, TryCatch #7 {FileNotFoundException -> 0x009c, blocks: (B:48:0x00a2, B:49:0x00a6, B:44:0x0098, B:41:0x0093), top: B:83:0x0093, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00a6 A[Catch: FileNotFoundException -> 0x009c, TRY_LEAVE, TryCatch #7 {FileNotFoundException -> 0x009c, blocks: (B:48:0x00a2, B:49:0x00a6, B:44:0x0098, B:41:0x0093), top: B:83:0x0093, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0082 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0093 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r8v0, types: [androidx.datastore.core.okio.b, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r8v1, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r8v12 */
    /* JADX WARN: Type inference failed for: r8v19, types: [java.io.Closeable] */
    /* JADX WARN: Type inference failed for: r8v24 */
    /* JADX WARN: Type inference failed for: r8v25 */
    /* JADX WARN: Type inference failed for: r8v6, types: [androidx.datastore.core.okio.b] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.Object f(androidx.datastore.core.okio.b r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 254
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.okio.b.f(androidx.datastore.core.okio.b, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.datastore.core.InterfaceC1069a
    public final void close() {
        ((AtomicBoolean) this.d.b).set(true);
    }

    @Override // androidx.datastore.core.d0
    public final Object e(C1085q c1085q) {
        return f(this, c1085q);
    }
}
