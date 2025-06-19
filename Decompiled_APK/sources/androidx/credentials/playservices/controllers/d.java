package androidx.credentials.playservices.controllers;

import android.content.Context;
import android.os.Bundle;
import android.os.CancellationSignal;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.C0473q;
import androidx.credentials.e;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.playservices.CredentialProviderPlayServicesImpl;
import java.util.concurrent.Executor;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class d extends b {
    public static final /* synthetic */ int d = 0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static final void b(CancellationSignal cancellationSignal, Function0 onResultOrException) {
        Intrinsics.checkNotNullParameter(onResultOrException, "onResultOrException");
        CredentialProviderPlayServicesImpl.Companion.getClass();
        if (androidx.credentials.playservices.b.a(cancellationSignal)) {
            return;
        }
        onResultOrException.invoke();
    }

    public static boolean c(Bundle resultData, Function2 conversionFn, Executor executor, e callback, CancellationSignal cancellationSignal) {
        Intrinsics.checkNotNullParameter(resultData, "resultData");
        Intrinsics.checkNotNullParameter(conversionFn, "conversionFn");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        if (!resultData.getBoolean("FAILURE_RESPONSE")) {
            return false;
        }
        b(cancellationSignal, new C0473q(executor, callback, conversionFn.invoke(resultData.getString("EXCEPTION_TYPE"), resultData.getString("EXCEPTION_MESSAGE")), 16));
        return true;
    }

    public static final boolean d(int i, Function2 cancelOnError, Function1 onError, CancellationSignal cancellationSignal) {
        Intrinsics.checkNotNullParameter(cancelOnError, "cancelOnError");
        Intrinsics.checkNotNullParameter(onError, "onError");
        if (i == -1) {
            return false;
        }
        J j = new J();
        j.a = new GetCredentialUnknownException(AbstractC0147y.c(i, "activity with result code: ", " indicating not RESULT_OK"));
        if (i == 0) {
            j.a = new GetCredentialCancellationException("activity is cancelled by the user.");
        }
        cancelOnError.invoke(cancellationSignal, new androidx.credentials.playservices.controllers.BeginSignIn.d(onError, j));
        return true;
    }
}
