package okhttp3;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;
import okio.InterfaceC5092i;

/* loaded from: classes3.dex */
public abstract class F {
    public static final D c(w wVar, File file) {
        Intrinsics.checkNotNullParameter(file, "file");
        Intrinsics.checkNotNullParameter(file, "<this>");
        return new D(wVar, file, 0);
    }

    public abstract long a();

    public abstract w b();

    public abstract void d(InterfaceC5092i interfaceC5092i);
}
