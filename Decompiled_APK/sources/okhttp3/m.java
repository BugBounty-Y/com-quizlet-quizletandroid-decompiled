package okhttp3;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements n {
    @Override // okhttp3.n
    public final void a(s url, List cookies) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(cookies, "cookies");
    }

    @Override // okhttp3.n
    public final List b(s url) {
        Intrinsics.checkNotNullParameter(url, "url");
        return kotlin.collections.K.a;
    }
}
