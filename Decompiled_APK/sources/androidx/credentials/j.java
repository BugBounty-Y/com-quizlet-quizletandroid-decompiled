package androidx.credentials;

import android.credentials.ClearCredentialStateException;
import android.os.OutcomeReceiver;
import android.util.Log;
import androidx.credentials.exceptions.ClearCredentialUnknownException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j implements OutcomeReceiver {
    public final /* synthetic */ c a;

    public j(c cVar) {
        this.a = cVar;
    }

    public final void onError(Throwable th) {
        ClearCredentialStateException error = i.m(th);
        Intrinsics.checkNotNullParameter(error, "error");
        Log.i("CredManProvService", "ClearCredentialStateException error returned from framework");
        this.a.b(new ClearCredentialUnknownException(null));
    }

    public final void onResult(Object obj) {
        Log.i("CredManProvService", "Clear result returned from framework: ");
        this.a.onResult((Void) obj);
    }
}
