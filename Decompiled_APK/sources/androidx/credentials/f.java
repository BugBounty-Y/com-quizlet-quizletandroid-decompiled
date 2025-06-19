package androidx.credentials;

import android.content.Context;
import android.os.CancellationSignal;
import androidx.credentials.exceptions.ClearCredentialProviderConfigurationException;
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class f {
    public final Context a;

    public f(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public static Object b(Context context, o request, com.quizlet.features.infra.google.d frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        CancellationSignal cancellationSignal = new CancellationSignal();
        c5028l.u(new androidx.compose.ui.scrollcapture.g(cancellationSignal, 2));
        d callback = new d(c5028l);
        androidx.arch.core.executor.a executor = new androidx.arch.core.executor.a(1);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        g gVarA = h.a(new h(context), request);
        if (gVarA == null) {
            callback.b(new GetCredentialProviderConfigurationException("getCredentialAsync no provider dependencies found - please ensure the desired provider dependencies are added"));
        } else {
            gVarA.onGetCredential(context, request, cancellationSignal, executor, callback);
        }
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    public Object a(a request, com.quizlet.features.infra.google.f frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        CancellationSignal cancellationSignal = new CancellationSignal();
        c5028l.u(new androidx.compose.ui.scrollcapture.g(cancellationSignal, 1));
        c callback = new c(c5028l);
        androidx.arch.core.executor.a executor = new androidx.arch.core.executor.a(1);
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        g gVarA = h.a(new h(this.a), "androidx.credentials.TYPE_CLEAR_CREDENTIAL_STATE");
        if (gVarA == null) {
            callback.b(new ClearCredentialProviderConfigurationException("clearCredentialStateAsync no provider dependencies found - please ensure the desired provider dependencies are added"));
        } else {
            gVarA.onClearCredential(request, cancellationSignal, executor, callback);
        }
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }
}
