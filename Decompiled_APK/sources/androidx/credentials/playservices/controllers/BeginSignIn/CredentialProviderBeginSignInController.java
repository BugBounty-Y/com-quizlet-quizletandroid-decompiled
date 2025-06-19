package androidx.credentials.playservices.controllers.BeginSignIn;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.ResultReceiver;
import android.util.Log;
import androidx.appcompat.app.y;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.platform.C0960p;
import androidx.credentials.e;
import androidx.credentials.exceptions.GetCredentialCancellationException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.GetCredentialInterruptedException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException;
import androidx.credentials.n;
import androidx.credentials.p;
import com.google.android.gms.auth.api.identity.SignInCredential;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.fido.fido2.api.common.AuthenticationExtensionsClientOutputs;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse;
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse;
import com.google.android.gms.fido.fido2.api.common.ErrorCode;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential;
import com.google.android.gms.internal.fido.T;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3441d3;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.LinkedHashMap;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class CredentialProviderBeginSignInController extends androidx.credentials.playservices.controllers.d {
    public static final /* synthetic */ int j = 0;
    public final Context e;
    public e f;
    public Executor g;
    public CancellationSignal h;
    public final CredentialProviderBeginSignInController$resultReceiver$1 i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Type inference failed for: r0v2, types: [androidx.credentials.playservices.controllers.BeginSignIn.CredentialProviderBeginSignInController$resultReceiver$1] */
    public CredentialProviderBeginSignInController(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.e = context;
        final Handler handler = new Handler(Looper.getMainLooper());
        this.i = new ResultReceiver(handler) { // from class: androidx.credentials.playservices.controllers.BeginSignIn.CredentialProviderBeginSignInController$resultReceiver$1
            @Override // android.os.ResultReceiver
            public final void onReceiveResult(int i, Bundle resultData) {
                Intrinsics.checkNotNullParameter(resultData, "resultData");
                C0960p c0960p = new C0960p(2, androidx.credentials.playservices.controllers.b.a, androidx.credentials.playservices.controllers.a.class, "getCredentialExceptionTypeToException", "getCredentialExceptionTypeToException$credentials_play_services_auth_release(Ljava/lang/String;Ljava/lang/String;)Landroidx/credentials/exceptions/GetCredentialException;", 0, 1);
                CredentialProviderBeginSignInController credentialProviderBeginSignInController = this.a;
                if (androidx.credentials.playservices.controllers.d.c(resultData, c0960p, credentialProviderBeginSignInController.g(), credentialProviderBeginSignInController.f(), credentialProviderBeginSignInController.h)) {
                    return;
                }
                int i2 = resultData.getInt("ACTIVITY_REQUEST_CODE");
                Intent intent = (Intent) resultData.getParcelable("RESULT_DATA");
                int i3 = androidx.credentials.playservices.controllers.b.c;
                if (i2 != i3) {
                    Log.w("BeginSignIn", "Returned request code " + i3 + " which  does not match what was given " + i2);
                    return;
                }
                if (androidx.credentials.playservices.controllers.d.d(i, a.a, new c(credentialProviderBeginSignInController, 0), credentialProviderBeginSignInController.h)) {
                    return;
                }
                try {
                    SignInCredential signInCredentialD = AbstractC3441d3.c(credentialProviderBeginSignInController.e).d(intent);
                    Intrinsics.checkNotNullExpressionValue(signInCredentialD, "getSignInCredentialFromIntent(...)");
                    androidx.credentials.playservices.controllers.d.b(credentialProviderBeginSignInController.h, new C0242g(29, credentialProviderBeginSignInController, credentialProviderBeginSignInController.e(signInCredentialD)));
                } catch (GetCredentialException e) {
                    androidx.credentials.playservices.controllers.d.b(credentialProviderBeginSignInController.h, new d(1, credentialProviderBeginSignInController, e));
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
                    androidx.credentials.playservices.controllers.d.b(credentialProviderBeginSignInController.h, new d(0, credentialProviderBeginSignInController, j2));
                } catch (Throwable th) {
                    androidx.credentials.playservices.controllers.d.b(credentialProviderBeginSignInController.h, new d(2, credentialProviderBeginSignInController, new GetCredentialUnknownException(th.getMessage())));
                }
            }
        };
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final p e(SignInCredential cred) throws GetCredentialCancellationException, GetPublicKeyCredentialDomException, GetCredentialUnknownException {
        y nVar;
        y nVar2;
        AuthenticatorErrorResponse authenticatorErrorResponse;
        String authenticationResponseJson;
        boolean z = true;
        String str = "response";
        Intrinsics.checkNotNullParameter(cred, "response");
        String password = cred.f;
        if (password != null) {
            String id = cred.a;
            Intrinsics.checkNotNullExpressionValue(id, "getId(...)");
            Intrinsics.d(password);
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(password, "password");
            Intrinsics.checkNotNullParameter(id, "id");
            Intrinsics.checkNotNullParameter(password, "password");
            Bundle bundle = new Bundle();
            bundle.putString("androidx.credentials.BUNDLE_KEY_ID", id);
            bundle.putString("androidx.credentials.BUNDLE_KEY_PASSWORD", password);
            nVar = new n(1, bundle, password);
        } else {
            JSONObject jSONObject = null;
            String idToken = cred.g;
            if (idToken != null) {
                String id2 = cred.a;
                Intrinsics.checkNotNullExpressionValue(id2, "getId(...)");
                Intrinsics.checkNotNullParameter(id2, "id");
                Intrinsics.checkNotNullParameter(idToken, "idToken");
                String str2 = cred.b;
                String str3 = str2 != null ? str2 : null;
                String str4 = cred.c;
                String str5 = str4 != null ? str4 : null;
                String str6 = cred.d;
                String str7 = str6 != null ? str6 : null;
                String str8 = cred.h;
                String str9 = str8 != null ? str8 : null;
                Uri uri = cred.e;
                nVar2 = new com.google.android.libraries.identity.googleid.c(id2, idToken, str3, str7, str5, uri != null ? uri : null, str9);
            } else {
                PublicKeyCredential publicKeyCredential = cred.i;
                if (publicKeyCredential != null) {
                    LinkedHashMap linkedHashMap = androidx.credentials.playservices.controllers.CreatePublicKeyCredential.a.a;
                    Intrinsics.checkNotNullParameter(cred, "cred");
                    JSONObject jSONObject2 = new JSONObject();
                    AuthenticatorErrorResponse authenticatorErrorResponse2 = publicKeyCredential.f;
                    AuthenticatorAssertionResponse authenticatorAssertionResponse = publicKeyCredential.e;
                    AuthenticatorAttestationResponse authenticatorAttestationResponse = publicKeyCredential.d;
                    if (authenticatorAttestationResponse != 0) {
                        authenticatorErrorResponse = authenticatorAttestationResponse;
                    } else if (authenticatorAssertionResponse != 0) {
                        authenticatorErrorResponse = authenticatorAssertionResponse;
                    } else {
                        if (authenticatorErrorResponse2 == null) {
                            throw new IllegalStateException("No response set.");
                        }
                        authenticatorErrorResponse = authenticatorErrorResponse2;
                    }
                    if (authenticatorErrorResponse instanceof AuthenticatorErrorResponse) {
                        AuthenticatorErrorResponse authenticatorErrorResponse3 = authenticatorErrorResponse;
                        ErrorCode code = authenticatorErrorResponse3.a;
                        Intrinsics.checkNotNullExpressionValue(code, "getErrorCode(...)");
                        Intrinsics.checkNotNullParameter(code, "code");
                        androidx.credentials.exceptions.domerrors.a aVar = (androidx.credentials.exceptions.domerrors.a) androidx.credentials.playservices.controllers.CreatePublicKeyCredential.a.a.get(code);
                        String str10 = authenticatorErrorResponse3.b;
                        if (aVar == null) {
                            throw new GetPublicKeyCredentialDomException(new androidx.credentials.exceptions.domerrors.a(26), AbstractC0147y.d("unknown fido gms exception - ", str10));
                        }
                        if (code == ErrorCode.NOT_ALLOWED_ERR && str10 != null && StringsKt.G(str10, "Unable to get sync account", false)) {
                            throw new GetCredentialCancellationException("Passkey retrieval was cancelled by the user.");
                        }
                        throw new GetPublicKeyCredentialDomException(aVar, str10);
                    }
                    try {
                        if (authenticatorErrorResponse instanceof AuthenticatorAssertionResponse) {
                            try {
                                JSONObject jSONObject3 = new JSONObject();
                                T t = publicKeyCredential.c;
                                if (t != null && t.m().length > 0) {
                                    jSONObject3.put("rawId", com.google.android.gms.common.util.c.g(t.m()));
                                }
                                String str11 = publicKeyCredential.h;
                                if (str11 != null) {
                                    jSONObject3.put("authenticatorAttachment", str11);
                                }
                                String str12 = publicKeyCredential.b;
                                if (str12 != null && authenticatorErrorResponse2 == null) {
                                    jSONObject3.put(DBUserFields.Names.USER_UPGRADE_TYPE, str12);
                                }
                                String str13 = publicKeyCredential.a;
                                if (str13 != null) {
                                    jSONObject3.put("id", str13);
                                }
                                if (authenticatorAssertionResponse != 0) {
                                    jSONObject = authenticatorAssertionResponse.a();
                                } else if (authenticatorAttestationResponse != 0) {
                                    jSONObject = authenticatorAttestationResponse.a();
                                } else {
                                    if (authenticatorErrorResponse2 != null) {
                                        try {
                                            jSONObject = new JSONObject();
                                            jSONObject.put("code", authenticatorErrorResponse2.a.a);
                                            String str14 = authenticatorErrorResponse2.b;
                                            if (str14 != null) {
                                                jSONObject.put("message", str14);
                                            }
                                            str = "error";
                                        } catch (JSONException e) {
                                            throw new RuntimeException("Error encoding AuthenticatorErrorResponse to JSON object", e);
                                        }
                                    }
                                    z = false;
                                }
                                if (jSONObject != null) {
                                    jSONObject3.put(str, jSONObject);
                                }
                                AuthenticationExtensionsClientOutputs authenticationExtensionsClientOutputs = publicKeyCredential.g;
                                if (authenticationExtensionsClientOutputs != null) {
                                    jSONObject3.put("clientExtensionResults", authenticationExtensionsClientOutputs.a());
                                } else if (z) {
                                    jSONObject3.put("clientExtensionResults", new JSONObject());
                                }
                                authenticationResponseJson = jSONObject3.toString();
                                Intrinsics.checkNotNullExpressionValue(authenticationResponseJson, "toJson(...)");
                            } catch (JSONException e2) {
                                throw new RuntimeException("Error encoding PublicKeyCredential to JSON object", e2);
                            }
                        } else {
                            Log.e("PublicKeyUtility", "AuthenticatorResponse expected assertion response but got: ".concat(authenticatorErrorResponse.getClass().getName()));
                            authenticationResponseJson = jSONObject2.toString();
                            Intrinsics.checkNotNullExpressionValue(authenticationResponseJson, "toString(...)");
                        }
                        Intrinsics.checkNotNullParameter(authenticationResponseJson, "authenticationResponseJson");
                        Intrinsics.checkNotNullParameter(authenticationResponseJson, "authenticationResponseJson");
                        Bundle bundle2 = new Bundle();
                        bundle2.putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", authenticationResponseJson);
                        nVar2 = new n(2, bundle2, authenticationResponseJson);
                    } catch (Throwable th) {
                        throw new GetCredentialUnknownException("The PublicKeyCredential response json had an unexpected exception when parsing: " + th.getMessage());
                    }
                } else {
                    Log.w("BeginSignIn", "Credential returned but no google Id or password or passkey found");
                    nVar = null;
                }
            }
            nVar = nVar2;
        }
        if (nVar != null) {
            return new p(nVar);
        }
        throw new GetCredentialUnknownException("When attempting to convert get response, null credential found");
    }

    public final e f() {
        e eVar = this.f;
        if (eVar != null) {
            return eVar;
        }
        Intrinsics.m("callback");
        throw null;
    }

    public final Executor g() {
        Executor executor = this.g;
        if (executor != null) {
            return executor;
        }
        Intrinsics.m("executor");
        throw null;
    }
}
