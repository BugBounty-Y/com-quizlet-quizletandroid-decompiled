package androidx.activity;

import android.content.res.Resources;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class O extends kotlin.jvm.internal.r implements Function1 {
    public static final O b = new O(1, 0);
    public static final O c = new O(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ O(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Resources resources = (Resources) obj;
                Intrinsics.checkNotNullParameter(resources, "resources");
                return Boolean.valueOf((resources.getConfiguration().uiMode & 48) == 32);
            default:
                Intrinsics.checkNotNullParameter((Resources) obj, "<anonymous parameter 0>");
                return Boolean.TRUE;
        }
    }
}
