package androidx.credentials.playservices;

import android.os.CancellationSignal;
import androidx.compose.animation.core.C0242g;
import java.util.concurrent.Executor;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ CancellationSignal a;
    public final /* synthetic */ Executor b;
    public final /* synthetic */ androidx.credentials.e c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(CancellationSignal cancellationSignal, Executor executor, androidx.credentials.e eVar) {
        super(1);
        this.a = cancellationSignal;
        this.b = executor;
        this.c = eVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        b bVar = CredentialProviderPlayServicesImpl.Companion;
        C0242g c0242g = new C0242g(28, this.b, this.c);
        bVar.getClass();
        b.b(this.a, c0242g);
        return Unit.a;
    }
}
