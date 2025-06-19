package kotlin.io;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class f {
    public final File a;

    public f(File root) {
        Intrinsics.checkNotNullParameter(root, "root");
        this.a = root;
    }

    public abstract File a();
}
