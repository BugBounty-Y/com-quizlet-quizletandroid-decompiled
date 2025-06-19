package androidx.datastore.core;

import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class U implements m0 {
    public static final LinkedHashSet c = new LinkedHashSet();
    public static final Object d = new Object();
    public final f0 a;
    public final kotlin.jvm.internal.r b;

    /* JADX WARN: Multi-variable type inference failed */
    public U(f0 serializer, Function0 produceFile) {
        T coordinatorProducer = T.a;
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(coordinatorProducer, "coordinatorProducer");
        Intrinsics.checkNotNullParameter(produceFile, "produceFile");
        this.a = serializer;
        this.b = (kotlin.jvm.internal.r) produceFile;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // androidx.datastore.core.m0
    public final n0 a() throws IOException {
        File file = ((File) this.b.invoke()).getCanonicalFile();
        synchronized (d) {
            String path = file.getAbsolutePath();
            LinkedHashSet linkedHashSet = c;
            if (linkedHashSet.contains(path)) {
                throw new IllegalStateException(("There are multiple DataStores active for the same file: " + path + ". You should either maintain your DataStore as a singleton or confirm that there is no two DataStore's active on the same file (by confirming that the scope is cancelled).").toString());
            }
            Intrinsics.checkNotNullExpressionValue(path, "path");
            linkedHashSet.add(path);
        }
        Intrinsics.checkNotNullExpressionValue(file, "file");
        f0 f0Var = this.a;
        Intrinsics.checkNotNullParameter(file, "it");
        Intrinsics.checkNotNullParameter(file, "file");
        String absolutePath = file.getCanonicalFile().getAbsolutePath();
        Intrinsics.checkNotNullExpressionValue(absolutePath, "file.canonicalFile.absolutePath");
        return new X(file, f0Var, N6.a(absolutePath), new androidx.compose.ui.input.nestedscroll.b(file, 19));
    }
}
