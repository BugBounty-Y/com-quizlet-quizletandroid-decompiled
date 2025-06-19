package androidx.credentials.playservices;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Looper;
import android.os.ResultReceiver;
import android.util.Log;
import androidx.appcompat.app.L;
import androidx.appcompat.app.Q;
import androidx.camera.camera2.internal.C0132i;
import com.google.android.gms.auth.api.identity.BeginSignInRequest;
import com.google.android.gms.auth.api.identity.GetSignInIntentRequest;
import com.google.android.gms.auth.api.identity.SavePasswordRequest;
import com.google.android.gms.auth.api.identity.h;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.tasks.g;
import com.google.android.gms.tasks.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public class HiddenActivity extends Activity {
    public static final /* synthetic */ int c = 0;
    public ResultReceiver a;
    public boolean b;

    public final void a(ResultReceiver resultReceiver, String str, String str2) {
        androidx.credentials.playservices.controllers.a aVar = androidx.credentials.playservices.controllers.b.a;
        androidx.credentials.playservices.controllers.a.b(resultReceiver, str, str2);
        finish();
    }

    @Override // android.app.Activity
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        ResultReceiver resultReceiver = this.a;
        if (resultReceiver != null) {
            androidx.credentials.playservices.controllers.a aVar = androidx.credentials.playservices.controllers.b.a;
            androidx.credentials.playservices.controllers.a.c(resultReceiver, i, i2, intent);
        }
        this.b = false;
        finish();
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        overridePendingTransition(0, 0);
        String stringExtra = getIntent().getStringExtra("TYPE");
        ResultReceiver resultReceiver = (ResultReceiver) getIntent().getParcelableExtra("RESULT_RECEIVER");
        this.a = resultReceiver;
        if (resultReceiver == null) {
            finish();
        }
        if (bundle != null) {
            this.b = bundle.getBoolean("androidx.credentials.playservices.AWAITING_RESULT", false);
        }
        if (this.b) {
            return;
        }
        if (stringExtra != null) {
            m mVarC = null;
            switch (stringExtra.hashCode()) {
                case -441061071:
                    if (stringExtra.equals("BEGIN_SIGN_IN")) {
                        BeginSignInRequest beginSignInRequest = (BeginSignInRequest) getIntent().getParcelableExtra("REQUEST_TYPE");
                        int intExtra = getIntent().getIntExtra("ACTIVITY_REQUEST_CODE", 1);
                        if (beginSignInRequest != null) {
                            com.google.android.gms.internal.p000authapi.b bVar = new com.google.android.gms.internal.p000authapi.b(this, new h());
                            com.google.android.gms.auth.api.identity.a aVarA = BeginSignInRequest.GoogleIdTokenRequestOptions.a();
                            aVarA.a = false;
                            aVarA.a();
                            new BeginSignInRequest.PasskeysRequestOptions(null, false, null);
                            new BeginSignInRequest.PasskeyJsonRequestOptions(false, null);
                            BeginSignInRequest.GoogleIdTokenRequestOptions googleIdTokenRequestOptions = beginSignInRequest.b;
                            u.h(googleIdTokenRequestOptions);
                            BeginSignInRequest.PasswordRequestOptions passwordRequestOptions = beginSignInRequest.a;
                            u.h(passwordRequestOptions);
                            BeginSignInRequest.PasskeysRequestOptions passkeysRequestOptions = beginSignInRequest.f;
                            u.h(passkeysRequestOptions);
                            BeginSignInRequest.PasskeyJsonRequestOptions passkeyJsonRequestOptions = beginSignInRequest.g;
                            u.h(passkeyJsonRequestOptions);
                            BeginSignInRequest beginSignInRequest2 = new BeginSignInRequest(passwordRequestOptions, googleIdTokenRequestOptions, bVar.l, beginSignInRequest.d, beginSignInRequest.e, passkeysRequestOptions, passkeyJsonRequestOptions, beginSignInRequest.h);
                            k kVarA = AbstractC2027eu.a();
                            kVarA.e = new Feature[]{new Feature("auth_api_credentials_begin_sign_in", 8L)};
                            kVarA.d = new com.airbnb.lottie.network.c(bVar, beginSignInRequest2);
                            kVarA.c = false;
                            kVarA.b = 1553;
                            mVarC = bVar.c(0, kVarA.a());
                            C0132i c0132i = new C0132i(new f(this, intExtra, 0), 20);
                            mVarC.getClass();
                            androidx.camera.core.impl.utils.executor.h hVar = g.a;
                            mVarC.d(hVar, c0132i);
                            final int i = 3;
                            mVarC.c(hVar, new com.google.android.gms.tasks.c(this) { // from class: androidx.credentials.playservices.e
                                public final /* synthetic */ HiddenActivity b;

                                {
                                    this.b = this;
                                }

                                @Override // com.google.android.gms.tasks.c
                                public final void t(Exception e) {
                                    String str = "CREATE_UNKNOWN";
                                    String str2 = "GET_NO_CREDENTIALS";
                                    HiddenActivity hiddenActivity = this.b;
                                    switch (i) {
                                        case 0:
                                            int i2 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver2 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver2);
                                            hiddenActivity.a(resultReceiver2, str, "During create public key credential, fido registration failure: " + e.getMessage());
                                            break;
                                        case 1:
                                            int i3 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver3 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver3);
                                            hiddenActivity.a(resultReceiver3, str, "During save password, found password failure response from one tap " + e.getMessage());
                                            break;
                                        case 2:
                                            int i4 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver4 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver4);
                                            hiddenActivity.a(resultReceiver4, str2, "During get sign-in intent, failure response from one tap: " + e.getMessage());
                                            break;
                                        default:
                                            int i5 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver5 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver5);
                                            hiddenActivity.a(resultReceiver5, str2, "During begin sign in, failure response from one tap: " + e.getMessage());
                                            break;
                                    }
                                }
                            });
                        }
                        if (mVarC == null) {
                            Log.i("HiddenActivity", "During begin sign in, params is null, nothing to launch for begin sign in");
                            finish();
                            return;
                        }
                        return;
                    }
                    break;
                case 15545322:
                    if (stringExtra.equals("CREATE_PUBLIC_KEY_CREDENTIAL")) {
                        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = (PublicKeyCredentialCreationOptions) getIntent().getParcelableExtra("REQUEST_TYPE");
                        int intExtra2 = getIntent().getIntExtra("ACTIVITY_REQUEST_CODE", 1);
                        if (publicKeyCredentialCreationOptions != null) {
                            com.google.android.gms.common.api.a aVar = com.google.android.gms.common.api.b.M0;
                            com.google.mlkit.common.sdkinternal.model.a aVar2 = new com.google.mlkit.common.sdkinternal.model.a(9);
                            Looper mainLooper = getMainLooper();
                            u.i(mainLooper, "Looper must not be null.");
                            com.google.android.gms.fido.fido2.a aVar3 = new com.google.android.gms.fido.fido2.a(this, this, com.google.android.gms.fido.fido2.a.l, aVar, new com.google.android.gms.common.api.d(aVar2, mainLooper));
                            k kVarA2 = AbstractC2027eu.a();
                            kVarA2.d = new L(aVar3, publicKeyCredentialCreationOptions);
                            kVarA2.b = 5407;
                            mVarC = aVar3.c(0, kVarA2.a());
                            C0132i c0132i2 = new C0132i(new f(this, intExtra2, 2), 17);
                            mVarC.getClass();
                            androidx.camera.core.impl.utils.executor.h hVar2 = g.a;
                            mVarC.d(hVar2, c0132i2);
                            final int i2 = 0;
                            mVarC.c(hVar2, new com.google.android.gms.tasks.c(this) { // from class: androidx.credentials.playservices.e
                                public final /* synthetic */ HiddenActivity b;

                                {
                                    this.b = this;
                                }

                                @Override // com.google.android.gms.tasks.c
                                public final void t(Exception e) {
                                    String str = "CREATE_UNKNOWN";
                                    String str2 = "GET_NO_CREDENTIALS";
                                    HiddenActivity hiddenActivity = this.b;
                                    switch (i2) {
                                        case 0:
                                            int i22 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver2 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver2);
                                            hiddenActivity.a(resultReceiver2, str, "During create public key credential, fido registration failure: " + e.getMessage());
                                            break;
                                        case 1:
                                            int i3 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver3 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver3);
                                            hiddenActivity.a(resultReceiver3, str, "During save password, found password failure response from one tap " + e.getMessage());
                                            break;
                                        case 2:
                                            int i4 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver4 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver4);
                                            hiddenActivity.a(resultReceiver4, str2, "During get sign-in intent, failure response from one tap: " + e.getMessage());
                                            break;
                                        default:
                                            int i5 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver5 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver5);
                                            hiddenActivity.a(resultReceiver5, str2, "During begin sign in, failure response from one tap: " + e.getMessage());
                                            break;
                                    }
                                }
                            });
                        }
                        if (mVarC == null) {
                            Log.w("HiddenActivity", "During create public key credential, request is null, so nothing to launch for public key credentials");
                            finish();
                            return;
                        }
                        return;
                    }
                    break;
                case 1246634622:
                    if (stringExtra.equals("CREATE_PASSWORD")) {
                        SavePasswordRequest savePasswordRequest = (SavePasswordRequest) getIntent().getParcelableExtra("REQUEST_TYPE");
                        int intExtra3 = getIntent().getIntExtra("ACTIVITY_REQUEST_CODE", 1);
                        if (savePasswordRequest != null) {
                            com.google.android.gms.internal.p000authapi.b bVar2 = new com.google.android.gms.internal.p000authapi.b(this, new com.google.android.gms.auth.api.identity.c());
                            SavePasswordRequest savePasswordRequest2 = new SavePasswordRequest(savePasswordRequest.a, bVar2.l, savePasswordRequest.c);
                            k kVarA3 = AbstractC2027eu.a();
                            kVarA3.e = new Feature[]{com.google.android.gms.internal.p000authapi.e.b};
                            Q q = new Q();
                            q.a = savePasswordRequest2;
                            kVarA3.d = q;
                            kVarA3.c = false;
                            kVarA3.b = 1536;
                            mVarC = bVar2.c(0, kVarA3.a());
                            C0132i c0132i3 = new C0132i(new f(this, intExtra3, 1), 18);
                            mVarC.getClass();
                            androidx.camera.core.impl.utils.executor.h hVar3 = g.a;
                            mVarC.d(hVar3, c0132i3);
                            final int i3 = 1;
                            mVarC.c(hVar3, new com.google.android.gms.tasks.c(this) { // from class: androidx.credentials.playservices.e
                                public final /* synthetic */ HiddenActivity b;

                                {
                                    this.b = this;
                                }

                                @Override // com.google.android.gms.tasks.c
                                public final void t(Exception e) {
                                    String str = "CREATE_UNKNOWN";
                                    String str2 = "GET_NO_CREDENTIALS";
                                    HiddenActivity hiddenActivity = this.b;
                                    switch (i3) {
                                        case 0:
                                            int i22 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver2 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver2);
                                            hiddenActivity.a(resultReceiver2, str, "During create public key credential, fido registration failure: " + e.getMessage());
                                            break;
                                        case 1:
                                            int i32 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver3 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver3);
                                            hiddenActivity.a(resultReceiver3, str, "During save password, found password failure response from one tap " + e.getMessage());
                                            break;
                                        case 2:
                                            int i4 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver4 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver4);
                                            hiddenActivity.a(resultReceiver4, str2, "During get sign-in intent, failure response from one tap: " + e.getMessage());
                                            break;
                                        default:
                                            int i5 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver5 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver5);
                                            hiddenActivity.a(resultReceiver5, str2, "During begin sign in, failure response from one tap: " + e.getMessage());
                                            break;
                                    }
                                }
                            });
                        }
                        if (mVarC == null) {
                            Log.i("HiddenActivity", "During save password, params is null, nothing to launch for create password");
                            finish();
                            return;
                        }
                        return;
                    }
                    break;
                case 1980564212:
                    if (stringExtra.equals("SIGN_IN_INTENT")) {
                        GetSignInIntentRequest getSignInIntentRequest = (GetSignInIntentRequest) getIntent().getParcelableExtra("REQUEST_TYPE");
                        int intExtra4 = getIntent().getIntExtra("ACTIVITY_REQUEST_CODE", 1);
                        if (getSignInIntentRequest != null) {
                            com.google.android.gms.internal.p000authapi.b bVar3 = new com.google.android.gms.internal.p000authapi.b(this, new h());
                            String str = getSignInIntentRequest.a;
                            u.h(str);
                            GetSignInIntentRequest getSignInIntentRequest2 = new GetSignInIntentRequest(getSignInIntentRequest.f, str, getSignInIntentRequest.b, bVar3.l, getSignInIntentRequest.d, getSignInIntentRequest.e);
                            k kVarA4 = AbstractC2027eu.a();
                            kVarA4.e = new Feature[]{com.google.android.gms.internal.p000authapi.e.c};
                            kVarA4.d = new com.airbnb.lottie.network.d(bVar3, getSignInIntentRequest2);
                            kVarA4.b = 1555;
                            mVarC = bVar3.c(0, kVarA4.a());
                            C0132i c0132i4 = new C0132i(new f(this, intExtra4, 3), 19);
                            mVarC.getClass();
                            androidx.camera.core.impl.utils.executor.h hVar4 = g.a;
                            mVarC.d(hVar4, c0132i4);
                            final int i4 = 2;
                            mVarC.c(hVar4, new com.google.android.gms.tasks.c(this) { // from class: androidx.credentials.playservices.e
                                public final /* synthetic */ HiddenActivity b;

                                {
                                    this.b = this;
                                }

                                @Override // com.google.android.gms.tasks.c
                                public final void t(Exception e) {
                                    String str2 = "CREATE_UNKNOWN";
                                    String str22 = "GET_NO_CREDENTIALS";
                                    HiddenActivity hiddenActivity = this.b;
                                    switch (i4) {
                                        case 0:
                                            int i22 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver2 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver2);
                                            hiddenActivity.a(resultReceiver2, str2, "During create public key credential, fido registration failure: " + e.getMessage());
                                            break;
                                        case 1:
                                            int i32 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str2 = "CREATE_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver3 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver3);
                                            hiddenActivity.a(resultReceiver3, str2, "During save password, found password failure response from one tap " + e.getMessage());
                                            break;
                                        case 2:
                                            int i42 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str22 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver4 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver4);
                                            hiddenActivity.a(resultReceiver4, str22, "During get sign-in intent, failure response from one tap: " + e.getMessage());
                                            break;
                                        default:
                                            int i5 = HiddenActivity.c;
                                            Intrinsics.checkNotNullParameter(e, "e");
                                            if ((e instanceof ApiException) && androidx.credentials.playservices.controllers.b.b.contains(Integer.valueOf(((ApiException) e).a.a))) {
                                                str22 = "GET_INTERRUPTED";
                                            }
                                            ResultReceiver resultReceiver5 = hiddenActivity.a;
                                            Intrinsics.d(resultReceiver5);
                                            hiddenActivity.a(resultReceiver5, str22, "During begin sign in, failure response from one tap: " + e.getMessage());
                                            break;
                                    }
                                }
                            });
                        }
                        if (mVarC == null) {
                            Log.i("HiddenActivity", "During get sign-in intent, params is null, nothing to launch for get sign-in intent");
                            finish();
                            return;
                        }
                        return;
                    }
                    break;
            }
        }
        Log.w("HiddenActivity", "Activity handed an unsupported type");
        finish();
    }

    @Override // android.app.Activity
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putBoolean("androidx.credentials.playservices.AWAITING_RESULT", this.b);
        super.onSaveInstanceState(outState);
    }
}
