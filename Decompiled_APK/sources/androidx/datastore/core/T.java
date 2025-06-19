package androidx.datastore.core;

import java.io.File;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T extends kotlin.jvm.internal.r implements Function1 {
    public static final T a = new T(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        File file = (File) obj;
        Intrinsics.checkNotNullParameter(file, "it");
        Intrinsics.checkNotNullParameter(file, "file");
        String filePath = file.getCanonicalFile().getAbsolutePath();
        Intrinsics.checkNotNullExpressionValue(filePath, "file.canonicalFile.absolutePath");
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        return new k0(filePath);
    }
}
