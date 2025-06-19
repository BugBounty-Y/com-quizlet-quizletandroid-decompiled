package androidx.core.widget;

import android.os.Parcel;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class l extends r implements Function1 {
    public static final l b = new l(1, 0);
    public static final l c = new l(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Parcel it2 = (Parcel) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return new k(it2);
            default:
                Parcel it3 = (Parcel) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return new m(it3);
        }
    }
}
