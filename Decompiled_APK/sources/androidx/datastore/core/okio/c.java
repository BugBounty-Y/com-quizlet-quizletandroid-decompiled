package androidx.datastore.core.okio;

import androidx.datastore.core.k0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import okio.n;
import okio.x;

/* loaded from: classes.dex */
public final class c extends r implements Function2 {
    public static final c a = new c(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        x path = (x) obj;
        Intrinsics.checkNotNullParameter(path, "path");
        Intrinsics.checkNotNullParameter((n) obj2, "<anonymous parameter 1>");
        Intrinsics.checkNotNullParameter(path, "path");
        String filePath = com.quizlet.quizletandroid.ui.folder.logging.a.f(path.a.s(), true).a.s();
        Intrinsics.checkNotNullParameter(filePath, "filePath");
        return new k0(filePath);
    }
}
