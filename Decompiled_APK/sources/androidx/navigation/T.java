package androidx.navigation;

import android.net.Uri;
import android.os.Bundle;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T {
    public static C1291m a(androidx.navigation.internal.d dVar, B destination, Bundle bundle, androidx.lifecycle.B hostLifecycleState, C1296s c1296s) {
        String id = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(id, "toString(...)");
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(hostLifecycleState, "hostLifecycleState");
        Intrinsics.checkNotNullParameter(id, "id");
        return new C1291m(dVar, destination, bundle, hostLifecycleState, c1296s, id, null);
    }

    public static String b(String s) {
        Intrinsics.checkNotNullParameter(s, "s");
        String strEncode = Uri.encode(s, null);
        Intrinsics.checkNotNullExpressionValue(strEncode, "encode(...)");
        return strEncode;
    }
}
