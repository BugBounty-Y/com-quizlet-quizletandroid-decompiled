package androidx.navigation.internal;

import androidx.navigation.C1301x;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1301x b;

    public /* synthetic */ k(C1301x c1301x, int i) {
        this.a = i;
        this.b = c1301x;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String key = (String) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(key, "key");
                break;
            default:
                Intrinsics.checkNotNullParameter(key, "key");
                break;
        }
        return Boolean.valueOf(!this.b.c().contains(key));
    }
}
