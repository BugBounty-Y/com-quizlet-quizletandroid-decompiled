package androidx.navigation;

import android.os.Bundle;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1299v implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Bundle b;

    public /* synthetic */ C1299v(Bundle bundle, int i) {
        this.a = i;
        this.b = bundle;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        String argName = (String) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(argName, "argName");
                Bundle source = this.b;
                Intrinsics.checkNotNullParameter(source, "source");
                return Boolean.valueOf(!AbstractC3335e2.a(source, argName));
            default:
                Intrinsics.checkNotNullParameter(argName, "key");
                Bundle source2 = this.b;
                Intrinsics.checkNotNullParameter(source2, "source");
                return Boolean.valueOf(!AbstractC3335e2.a(source2, argName));
        }
    }
}
