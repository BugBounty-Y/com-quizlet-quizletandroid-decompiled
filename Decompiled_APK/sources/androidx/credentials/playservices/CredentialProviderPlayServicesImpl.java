package androidx.credentials.playservices;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.CancellationSignal;
import android.util.Log;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.camera2.internal.j0;
import androidx.compose.foundation.C0473q;
import androidx.credentials.exceptions.ClearCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialUnsupportedException;
import androidx.credentials.g;
import androidx.credentials.o;
import androidx.credentials.playservices.controllers.BeginSignIn.CredentialProviderBeginSignInController;
import androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController;
import androidx.credentials.q;
import androidx.credentials.r;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.auth.api.identity.GetSignInIntentRequest;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.m;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.Executor;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class CredentialProviderPlayServicesImpl implements g {

    @NotNull
    public static final b Companion = new b();
    public static final int MIN_GMS_APK_VERSION = 230815045;
    public static final int MIN_GMS_APK_VERSION_DIGITAL_CRED = 243100000;
    public static final int MIN_GMS_APK_VERSION_RESTORE_CRED = 242200000;

    @NotNull
    private static final String TAG = "PlayServicesImpl";

    @NotNull
    private final Context context;

    @NotNull
    private GoogleApiAvailability googleApiAvailability;

    public CredentialProviderPlayServicesImpl(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
        Intrinsics.checkNotNullExpressionValue(googleApiAvailability, "getInstance(...)");
        this.googleApiAvailability = googleApiAvailability;
    }

    public static /* synthetic */ void getGoogleApiAvailability$annotations() {
    }

    private final int isGooglePlayServicesAvailable(Context context, int i) {
        return this.googleApiAvailability.c(context, i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onClearCredential$lambda$1(CancellationSignal cancellationSignal, Executor executor, androidx.credentials.e eVar, Exception e) {
        Intrinsics.checkNotNullParameter(e, "e");
        Log.w(TAG, "Clearing restore credential failed", e);
        J j = new J();
        j.a = new ClearCredentialUnknownException("Clear restore credential failed for unknown reason.");
        if ((e instanceof ApiException) && ((ApiException) e).a.a == 40201) {
            j.a = new ClearCredentialUnknownException("The restore credential internal service had a failure.");
        }
        b bVar = Companion;
        C0473q c0473q = new C0473q(executor, eVar, j);
        bVar.getClass();
        b.b(cancellationSignal, c0473q);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void onClearCredential$lambda$4(CredentialProviderPlayServicesImpl credentialProviderPlayServicesImpl, CancellationSignal cancellationSignal, Executor executor, androidx.credentials.e eVar, Exception e) {
        Intrinsics.checkNotNullParameter(e, "e");
        b bVar = Companion;
        C0473q c0473q = new C0473q(e, executor, eVar, 15);
        bVar.getClass();
        b.b(cancellationSignal, c0473q);
    }

    @NotNull
    public final GoogleApiAvailability getGoogleApiAvailability() {
        return this.googleApiAvailability;
    }

    @Override // androidx.credentials.g
    public boolean isAvailableOnDevice() {
        return isAvailableOnDevice(MIN_GMS_APK_VERSION);
    }

    @Override // androidx.credentials.g
    public void onClearCredential(@NotNull androidx.credentials.a request, CancellationSignal cancellationSignal, @NotNull Executor executor, @NotNull androidx.credentials.e callback) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        Companion.getClass();
        if (b.a(cancellationSignal)) {
            return;
        }
        request.getClass();
        Task taskE = AbstractC3441d3.c(this.context).e();
        C0132i c0132i = new C0132i(new d(cancellationSignal, executor, callback), 16);
        m mVar = (m) taskE;
        mVar.getClass();
        mVar.d(com.google.android.gms.tasks.g.a, c0132i);
        mVar.o(new j0(this, cancellationSignal, executor, callback));
    }

    public void onCreateCredential(@NotNull Context context, @NotNull androidx.credentials.b request, CancellationSignal cancellationSignal, @NotNull Executor executor, @NotNull androidx.credentials.e callback) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        Companion.getClass();
        if (!b.a(cancellationSignal)) {
            throw new UnsupportedOperationException("Create Credential request is unsupported, not password or publickeycredential");
        }
    }

    public void onGetCredential(@NotNull Context context, @NotNull r pendingGetCredentialHandle, CancellationSignal cancellationSignal, @NotNull Executor executor, @NotNull androidx.credentials.e callback) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(pendingGetCredentialHandle, "pendingGetCredentialHandle");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
    }

    public void onPrepareCredential(@NotNull o request, CancellationSignal cancellationSignal, @NotNull Executor executor, @NotNull androidx.credentials.e callback) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
    }

    public final void setGoogleApiAvailability(@NotNull GoogleApiAvailability googleApiAvailability) {
        Intrinsics.checkNotNullParameter(googleApiAvailability, "<set-?>");
        this.googleApiAvailability = googleApiAvailability;
    }

    public final boolean isAvailableOnDevice(int i) {
        int iIsGooglePlayServicesAvailable = isGooglePlayServicesAvailable(this.context, i);
        boolean z = iIsGooglePlayServicesAvailable == 0;
        if (!z) {
            Log.w(TAG, "Connection with Google Play Services was not successful. Connection result is: " + new ConnectionResult(iIsGooglePlayServicesAvailable));
        }
        return z;
    }

    @Override // androidx.credentials.g
    public void onGetCredential(@NotNull Context context, @NotNull o request, CancellationSignal cancellationSignal, @NotNull Executor executor, @NotNull androidx.credentials.e callback) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(executor, "executor");
        Intrinsics.checkNotNullParameter(callback, "callback");
        Companion.getClass();
        if (b.a(cancellationSignal)) {
            return;
        }
        Intrinsics.checkNotNullParameter(request, "request");
        for (q qVar : request.a) {
        }
        Companion.getClass();
        Intrinsics.checkNotNullParameter(request, "request");
        List<q> list = request.a;
        for (q qVar2 : list) {
        }
        Companion.getClass();
        Intrinsics.checkNotNullParameter(request, "request");
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            if (((q) it2.next()) instanceof com.google.android.libraries.identity.googleid.b) {
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController = new CredentialProviderGetSignInIntentController(context);
                Context context2 = credentialProviderGetSignInIntentController.e;
                Intrinsics.checkNotNullParameter(request, "request");
                Intrinsics.checkNotNullParameter(callback, "callback");
                Intrinsics.checkNotNullParameter(executor, "executor");
                credentialProviderGetSignInIntentController.h = cancellationSignal;
                Intrinsics.checkNotNullParameter(callback, "<set-?>");
                credentialProviderGetSignInIntentController.f = callback;
                Intrinsics.checkNotNullParameter(executor, "<set-?>");
                credentialProviderGetSignInIntentController.g = executor;
                Companion.getClass();
                if (b.a(cancellationSignal)) {
                    return;
                }
                try {
                    GetSignInIntentRequest getSignInIntentRequestE = CredentialProviderGetSignInIntentController.e(request);
                    Intent intent = new Intent(context2, (Class<?>) HiddenActivity.class);
                    intent.putExtra("REQUEST_TYPE", getSignInIntentRequestE);
                    androidx.credentials.playservices.controllers.b.a(credentialProviderGetSignInIntentController.i, intent, "SIGN_IN_INTENT");
                    context2.startActivity(intent);
                    return;
                } catch (Exception e) {
                    if (e instanceof GetCredentialUnsupportedException) {
                        androidx.credentials.playservices.controllers.d.b(cancellationSignal, new androidx.credentials.playservices.controllers.BeginSignIn.d(8, credentialProviderGetSignInIntentController, (GetCredentialUnsupportedException) e));
                        return;
                    } else {
                        androidx.credentials.playservices.controllers.d.b(cancellationSignal, new androidx.compose.ui.input.nestedscroll.b(credentialProviderGetSignInIntentController, 18));
                        return;
                    }
                }
            }
        }
        CredentialProviderBeginSignInController credentialProviderBeginSignInController = new CredentialProviderBeginSignInController(context);
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(callback, "callback");
        Intrinsics.checkNotNullParameter(executor, "executor");
        credentialProviderBeginSignInController.h = cancellationSignal;
        Intrinsics.checkNotNullParameter(callback, "<set-?>");
        credentialProviderBeginSignInController.f = callback;
        Intrinsics.checkNotNullParameter(executor, "<set-?>");
        credentialProviderBeginSignInController.g = executor;
        Companion.getClass();
        if (b.a(cancellationSignal)) {
            return;
        }
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(request, "request");
        Context context3 = credentialProviderBeginSignInController.e;
        Intrinsics.checkNotNullParameter(context3, "context");
        BeginSignInRequest.PasswordRequestOptions passwordRequestOptions = new BeginSignInRequest.PasswordRequestOptions(false);
        com.google.android.gms.auth.api.identity.a aVarA = BeginSignInRequest.GoogleIdTokenRequestOptions.a();
        aVarA.a = false;
        BeginSignInRequest.GoogleIdTokenRequestOptions googleIdTokenRequestOptionsA = aVarA.a();
        BeginSignInRequest.PasskeysRequestOptions passkeysRequestOptions = new BeginSignInRequest.PasskeysRequestOptions(null, false, null);
        BeginSignInRequest.PasskeyJsonRequestOptions passkeyJsonRequestOptions = new BeginSignInRequest.PasskeyJsonRequestOptions(false, null);
        PackageManager packageManager = context3.getPackageManager();
        Intrinsics.checkNotNullExpressionValue(packageManager, "getPackageManager(...)");
        int i = packageManager.getPackageInfo("com.google.android.gms", 0).versionCode;
        boolean z = false;
        BeginSignInRequest.GoogleIdTokenRequestOptions googleIdTokenRequestOptions = googleIdTokenRequestOptionsA;
        for (q qVar3 : list) {
            if (qVar3 instanceof com.google.android.libraries.identity.googleid.a) {
                com.google.android.libraries.identity.googleid.a aVar = (com.google.android.libraries.identity.googleid.a) qVar3;
                com.google.android.gms.auth.api.identity.a aVarA2 = BeginSignInRequest.GoogleIdTokenRequestOptions.a();
                aVarA2.c = aVar.e;
                String str = aVar.d;
                u.e(str);
                aVarA2.b = str;
                aVarA2.a = true;
                Intrinsics.checkNotNullExpressionValue(aVarA2, "setSupported(...)");
                BeginSignInRequest.GoogleIdTokenRequestOptions googleIdTokenRequestOptionsA2 = aVarA2.a();
                Intrinsics.checkNotNullExpressionValue(googleIdTokenRequestOptionsA2, "build(...)");
                z = z || aVar.f;
                googleIdTokenRequestOptions = googleIdTokenRequestOptionsA2;
            }
        }
        BeginSignInRequest beginSignInRequest = new BeginSignInRequest(passwordRequestOptions, googleIdTokenRequestOptions, null, z, 0, passkeysRequestOptions, passkeyJsonRequestOptions, false);
        Intrinsics.checkNotNullExpressionValue(beginSignInRequest, "build(...)");
        Intent intent2 = new Intent(context3, (Class<?>) HiddenActivity.class);
        intent2.putExtra("REQUEST_TYPE", beginSignInRequest);
        androidx.credentials.playservices.controllers.b.a(credentialProviderBeginSignInController.i, intent2, "BEGIN_SIGN_IN");
        try {
            context3.startActivity(intent2);
        } catch (Exception unused) {
            androidx.credentials.playservices.controllers.d.b(cancellationSignal, new androidx.compose.ui.input.nestedscroll.b(credentialProviderBeginSignInController, 17));
        }
    }
}
