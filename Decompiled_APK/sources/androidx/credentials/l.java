package androidx.credentials;

import android.content.Context;
import android.credentials.CredentialManager;
import android.credentials.GetCredentialException;
import android.credentials.GetCredentialRequest;
import android.credentials.GetCredentialResponse;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.OutcomeReceiver;
import android.util.Log;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class l implements g {
    public final CredentialManager a;

    public l(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = i.n(context.getSystemService("credential"));
    }

    @Override // androidx.credentials.g
    public final boolean isAvailableOnDevice() {
        return Build.VERSION.SDK_INT >= 34 && this.a != null;
    }

    @Override // androidx.credentials.g
    public final void onClearCredential(a request, CancellationSignal cancellationSignal, Executor executor, e callback) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        Log.i("CredManProvService", "In CredentialProviderFrameworkImpl onClearCredential");
        c cVar = (c) callback;
        androidx.compose.ui.input.nestedscroll.b bVar = new androidx.compose.ui.input.nestedscroll.b(cVar, 15);
        CredentialManager credentialManager = this.a;
        if (credentialManager == null) {
            bVar.invoke();
            return;
        }
        j jVar = new j(cVar);
        Intrinsics.d(credentialManager);
        i.u();
        credentialManager.clearCredentialState(androidx.compose.foundation.text.input.internal.p.e(new Bundle()), cancellationSignal, (androidx.arch.core.executor.a) executor, jVar);
    }

    @Override // androidx.credentials.g
    public final void onGetCredential(Context context, o request, CancellationSignal cancellationSignal, Executor executor, e callback) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        d dVar = (d) callback;
        androidx.compose.ui.input.nestedscroll.b bVar = new androidx.compose.ui.input.nestedscroll.b(dVar, 16);
        CredentialManager credentialManager = this.a;
        if (credentialManager == null) {
            bVar.invoke();
            return;
        }
        k kVar = new k(dVar, this);
        Intrinsics.d(credentialManager);
        i.C();
        Intrinsics.checkNotNullParameter(request, "request");
        Bundle bundle = new Bundle();
        request.getClass();
        bundle.putBoolean("androidx.credentials.BUNDLE_KEY_PREFER_IDENTITY_DOC_UI", false);
        bundle.putBoolean("androidx.credentials.BUNDLE_KEY_PREFER_IMMEDIATELY_AVAILABLE_CREDENTIALS", false);
        bundle.putParcelable("androidx.credentials.BUNDLE_KEY_PREFER_UI_BRANDING_COMPONENT_NAME", null);
        GetCredentialRequest.Builder builderR = i.r(bundle);
        for (q qVar : request.a) {
            i.D();
            qVar.getClass();
            builderR.addCredentialOption(i.p(qVar.a, qVar.b).setIsSystemProviderRequired(true).setAllowedProviders(qVar.c).build());
        }
        GetCredentialRequest getCredentialRequestBuild = builderR.build();
        Intrinsics.checkNotNullExpressionValue(getCredentialRequestBuild, "builder.build()");
        credentialManager.getCredential(context, getCredentialRequestBuild, cancellationSignal, (androidx.arch.core.executor.a) executor, (OutcomeReceiver<GetCredentialResponse, GetCredentialException>) kVar);
    }
}
