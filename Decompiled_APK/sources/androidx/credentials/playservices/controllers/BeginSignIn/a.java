package androidx.credentials.playservices.controllers.BeginSignIn;

import android.os.CancellationSignal;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function2 {
    public static final a a = new a(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Function0 f = (Function0) obj2;
        Intrinsics.checkNotNullParameter(f, "f");
        int i = androidx.credentials.playservices.controllers.d.d;
        int i2 = CredentialProviderBeginSignInController.j;
        androidx.credentials.playservices.controllers.d.b((CancellationSignal) obj, f);
        return Unit.a;
    }
}
