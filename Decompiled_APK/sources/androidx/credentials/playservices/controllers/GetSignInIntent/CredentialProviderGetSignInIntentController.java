package androidx.credentials.playservices.controllers.GetSignInIntent;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.ResultReceiver;
import android.util.Log;
import androidx.compose.ui.platform.C0960p;
import androidx.credentials.e;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.GetCredentialInterruptedException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialUnsupportedException;
import androidx.credentials.o;
import androidx.credentials.p;
import androidx.credentials.playservices.controllers.BeginSignIn.c;
import androidx.credentials.playservices.controllers.d;
import com.google.android.gms.auth.api.identity.GetSignInIntentRequest;
import com.google.android.gms.auth.api.identity.SignInCredential;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class CredentialProviderGetSignInIntentController extends d {
    public static final /* synthetic */ int j = 0;
    public final Context e;
    public e f;
    public Executor g;
    public CancellationSignal h;
    public final CredentialProviderGetSignInIntentController$resultReceiver$1 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r0v2, types: [androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController$resultReceiver$1] */
    public CredentialProviderGetSignInIntentController(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.e = context;
        final Handler handler = new Handler(Looper.getMainLooper());
        this.i = new ResultReceiver(handler) { // from class: androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController$resultReceiver$1
            @Override // android.os.ResultReceiver
            public final void onReceiveResult(int i, Bundle resultData) {
                Intrinsics.checkNotNullParameter(resultData, "resultData");
                C0960p c0960p = new C0960p(2, androidx.credentials.playservices.controllers.b.a, androidx.credentials.playservices.controllers.a.class, "getCredentialExceptionTypeToException", "getCredentialExceptionTypeToException$credentials_play_services_auth_release(Ljava/lang/String;Ljava/lang/String;)Landroidx/credentials/exceptions/GetCredentialException;", 0, 2);
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController = this.a;
                if (d.c(resultData, c0960p, credentialProviderGetSignInIntentController.h(), credentialProviderGetSignInIntentController.g(), credentialProviderGetSignInIntentController.h)) {
                    return;
                }
                int i2 = resultData.getInt("ACTIVITY_REQUEST_CODE");
                Intent intent = (Intent) resultData.getParcelable("RESULT_DATA");
                int i3 = androidx.credentials.playservices.controllers.b.c;
                if (i2 != i3) {
                    Log.w("GetSignInIntent", "Returned request code " + i3 + " which  does not match what was given " + i2);
                    return;
                }
                if (d.d(i, a.a, new c(credentialProviderGetSignInIntentController, 1), credentialProviderGetSignInIntentController.h)) {
                    return;
                }
                try {
                    SignInCredential signInCredentialD = AbstractC3441d3.c(credentialProviderGetSignInIntentController.e).d(intent);
                    Intrinsics.checkNotNullExpressionValue(signInCredentialD, "getSignInCredentialFromIntent(...)");
                    d.b(credentialProviderGetSignInIntentController.h, new androidx.credentials.playservices.controllers.BeginSignIn.d(4, credentialProviderGetSignInIntentController, credentialProviderGetSignInIntentController.f(signInCredentialD)));
                } catch (GetCredentialException e) {
                    d.b(credentialProviderGetSignInIntentController.h, new androidx.credentials.playservices.controllers.BeginSignIn.d(6, credentialProviderGetSignInIntentController, e));
                } catch (ApiException e2) {
                    J j2 = new J();
                    j2.a = new GetCredentialUnknownException(e2.getMessage());
                    int i4 = e2.a.a;
                    if (i4 == 16) {
                        j2.a = new GetCredentialCancellationException(e2.getMessage());
                    } else {
                        if (androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(i4))) {
                            j2.a = new GetCredentialInterruptedException(e2.getMessage());
                        }
                    }
                    d.b(credentialProviderGetSignInIntentController.h, new androidx.credentials.playservices.controllers.BeginSignIn.d(5, credentialProviderGetSignInIntentController, j2));
                } catch (Throwable th) {
                    d.b(credentialProviderGetSignInIntentController.h, new androidx.credentials.playservices.controllers.BeginSignIn.d(7, credentialProviderGetSignInIntentController, new GetCredentialUnknownException(th.getMessage())));
                }
            }
        };
    }

    public static GetSignInIntentRequest e(o request) {
        Intrinsics.checkNotNullParameter(request, "request");
        if (request.a.size() != 1) {
            throw new GetCredentialUnsupportedException("GetSignInWithGoogleOption cannot be combined with other options.");
        }
        Object obj = request.a.get(0);
        Intrinsics.e(obj, "null cannot be cast to non-null type com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption");
        String str = ((com.google.android.libraries.identity.googleid.b) obj).d;
        u.h(str);
        GetSignInIntentRequest getSignInIntentRequest = new GetSignInIntentRequest(0, str, null, null, null, false);
        Intrinsics.checkNotNullExpressionValue(getSignInIntentRequest, "build(...)");
        return getSignInIntentRequest;
    }

    public final p f(SignInCredential response) throws GetCredentialUnknownException {
        Intrinsics.checkNotNullParameter(response, "response");
        String idToken = response.g;
        com.google.android.libraries.identity.googleid.c cVar = null;
        if (idToken != null) {
            Intrinsics.checkNotNullParameter(response, "response");
            String id = response.a;
            Intrinsics.checkNotNullExpressionValue(id, "getId(...)");
            Intrinsics.checkNotNullParameter(id, "id");
            try {
                Intrinsics.d(idToken);
                Intrinsics.checkNotNullParameter(idToken, "idToken");
                String str = response.b;
                String str2 = str != null ? str : null;
                String str3 = response.c;
                String str4 = str3 != null ? str3 : null;
                String str5 = response.d;
                String str6 = str5 != null ? str5 : null;
                String str7 = response.h;
                String str8 = str7 != null ? str7 : null;
                Uri uri = response.e;
                cVar = new com.google.android.libraries.identity.googleid.c(id, idToken, str2, str6, str4, uri != null ? uri : null, str8);
            } catch (Exception unused) {
                throw new GetCredentialUnknownException("When attempting to convert get response, null Google ID Token found");
            }
        } else {
            Log.w("GetSignInIntent", "Credential returned but no google Id found");
        }
        if (cVar != null) {
            return new p(cVar);
        }
        throw new GetCredentialUnknownException("When attempting to convert get response, null credential found");
    }

    public final e g() {
        e eVar = this.f;
        if (eVar != null) {
            return eVar;
        }
        Intrinsics.m("callback");
        throw null;
    }

    public final Executor h() {
        Executor executor = this.g;
        if (executor != null) {
            return executor;
        }
        Intrinsics.m("executor");
        throw null;
    }
}
