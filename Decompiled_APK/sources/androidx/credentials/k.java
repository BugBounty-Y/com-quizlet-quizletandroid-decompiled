package androidx.credentials;

import android.credentials.Credential;
import android.credentials.GetCredentialResponse;
import android.os.Bundle;
import android.os.OutcomeReceiver;
import android.util.Log;
import androidx.appcompat.app.y;
import androidx.credentials.exceptions.NoCredentialException;
import androidx.credentials.internal.FrameworkClassParsingException;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class k implements OutcomeReceiver {
    public final /* synthetic */ d a;
    public final /* synthetic */ l b;

    public k(d dVar, l lVar) {
        this.a = dVar;
        this.b = lVar;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0089  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onError(java.lang.Throwable r6) throws androidx.credentials.internal.FrameworkClassParsingException {
        /*
            r5 = this;
            android.credentials.GetCredentialException r6 = androidx.credentials.i.q(r6)
            java.lang.String r0 = "error"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r1 = "CredManProvService"
            java.lang.String r2 = "GetCredentialResponse error returned from framework"
            android.util.Log.i(r1, r2)
            androidx.credentials.d r1 = r5.a
            androidx.credentials.l r2 = r5.b
            r2.getClass()
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = androidx.compose.foundation.text.input.internal.p.t(r6)
            java.lang.String r2 = "error.type"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            java.lang.String r6 = androidx.compose.foundation.text.input.internal.p.D(r6)
            java.lang.String r2 = "errorType"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r2)
            int r2 = r0.hashCode()
            switch(r2) {
                case -781118336: goto L81;
                case -408155724: goto L72;
                case -45448328: goto L63;
                case 580557411: goto L54;
                case 627896683: goto L44;
                case 1594095913: goto L34;
                default: goto L33;
            }
        L33:
            goto L89
        L34:
            java.lang.String r2 = "androidx.credentials.TYPE_GET_CREDENTIAL_PROVIDER_CONFIGURATION_EXCEPTION"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto L3d
            goto L89
        L3d:
            androidx.credentials.exceptions.GetCredentialProviderConfigurationException r0 = new androidx.credentials.exceptions.GetCredentialProviderConfigurationException
            r0.<init>(r6)
            goto Lc6
        L44:
            java.lang.String r2 = "android.credentials.GetCredentialException.TYPE_NO_CREDENTIAL"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto L4d
            goto L89
        L4d:
            androidx.credentials.exceptions.NoCredentialException r0 = new androidx.credentials.exceptions.NoCredentialException
            r0.<init>(r6)
            goto Lc6
        L54:
            java.lang.String r2 = "android.credentials.GetCredentialException.TYPE_USER_CANCELED"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto L5d
            goto L89
        L5d:
            androidx.credentials.exceptions.GetCredentialCancellationException r0 = new androidx.credentials.exceptions.GetCredentialCancellationException
            r0.<init>(r6)
            goto Lc6
        L63:
            java.lang.String r2 = "android.credentials.GetCredentialException.TYPE_INTERRUPTED"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto L6c
            goto L89
        L6c:
            androidx.credentials.exceptions.GetCredentialInterruptedException r0 = new androidx.credentials.exceptions.GetCredentialInterruptedException
            r0.<init>(r6)
            goto Lc6
        L72:
            java.lang.String r2 = "androidx.credentials.TYPE_GET_CREDENTIAL_UNSUPPORTED_EXCEPTION"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto L7b
            goto L89
        L7b:
            androidx.credentials.exceptions.GetCredentialUnsupportedException r0 = new androidx.credentials.exceptions.GetCredentialUnsupportedException
            r0.<init>(r6)
            goto Lc6
        L81:
            java.lang.String r2 = "android.credentials.GetCredentialException.TYPE_UNKNOWN"
            boolean r2 = r0.equals(r2)
            if (r2 != 0) goto Lc1
        L89:
            java.lang.String r2 = "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION"
            r3 = 0
            boolean r4 = kotlin.text.D.r(r0, r2, r3)
            if (r4 == 0) goto Lbb
            int r4 = androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialException.a
            if (r6 == 0) goto L9b
            java.lang.String r6 = r6.toString()
            goto L9c
        L9b:
            r6 = 0
        L9c:
            java.lang.String r4 = "type"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r4)
            boolean r2 = kotlin.text.D.r(r0, r2, r3)     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
            if (r2 == 0) goto Lae
            int r2 = androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException.b     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
            androidx.credentials.exceptions.GetCredentialException r0 = com.google.android.gms.internal.mlkit_vision_barcode.E6.b(r0, r6)     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
            goto Lc6
        Lae:
            androidx.credentials.internal.FrameworkClassParsingException r2 = new androidx.credentials.internal.FrameworkClassParsingException     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
            r2.<init>()     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
            throw r2     // Catch: androidx.credentials.internal.FrameworkClassParsingException -> Lb4
        Lb4:
            androidx.credentials.exceptions.GetCredentialCustomException r2 = new androidx.credentials.exceptions.GetCredentialCustomException
            r2.<init>(r6, r0)
        Lb9:
            r0 = r2
            goto Lc6
        Lbb:
            androidx.credentials.exceptions.GetCredentialCustomException r2 = new androidx.credentials.exceptions.GetCredentialCustomException
            r2.<init>(r6, r0)
            goto Lb9
        Lc1:
            androidx.credentials.exceptions.GetCredentialUnknownException r0 = new androidx.credentials.exceptions.GetCredentialUnknownException
            r0.<init>(r6)
        Lc6:
            r1.b(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.credentials.k.onError(java.lang.Throwable):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public final void onResult(Object obj) throws FrameworkClassParsingException, NoCredentialException {
        y mVar;
        n nVar;
        GetCredentialResponse response = i.s(obj);
        Intrinsics.checkNotNullParameter(response, "response");
        Log.i("CredManProvService", "GetCredentialResponse returned from framework");
        d dVar = this.a;
        this.b.getClass();
        Intrinsics.checkNotNullParameter(response, "response");
        Credential credential = response.getCredential();
        Intrinsics.checkNotNullExpressionValue(credential, "response.credential");
        String type = credential.getType();
        Intrinsics.checkNotNullExpressionValue(type, "credential.type");
        Bundle data = credential.getData();
        Intrinsics.checkNotNullExpressionValue(data, "credential.data");
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(data, "data");
        try {
        } catch (FrameworkClassParsingException unused) {
            mVar = new m(data, type);
        }
        switch (type.hashCode()) {
            case -1678407252:
                if (type.equals("androidx.credentials.TYPE_DIGITAL_CREDENTIAL")) {
                    Intrinsics.checkNotNullParameter(data, "data");
                    try {
                        String jsonString = data.getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                        Intrinsics.d(jsonString);
                        nVar = new n(data, "androidx.credentials.TYPE_DIGITAL_CREDENTIAL");
                        Intrinsics.checkNotNullParameter(jsonString, "jsonString");
                        if (jsonString.length() != 0) {
                            try {
                                new JSONObject(jsonString);
                                mVar = nVar;
                                dVar.onResult(new p(mVar));
                                return;
                            } catch (Exception unused2) {
                            }
                        }
                        throw new IllegalArgumentException("credentialJson must not be empty, and must be a valid JSON");
                    } catch (Exception unused3) {
                        throw new FrameworkClassParsingException();
                    }
                }
                throw new FrameworkClassParsingException();
            case -1072734346:
                if (type.equals("androidx.credentials.TYPE_RESTORE_CREDENTIAL")) {
                    Intrinsics.checkNotNullParameter(data, "data");
                    String jsonString2 = data.getString("androidx.credentials.BUNDLE_KEY_GET_RESTORE_CREDENTIAL_RESPONSE");
                    if (jsonString2 == null) {
                        throw new NoCredentialException("The device does not contain a restore credential.");
                    }
                    nVar = new n(data, "androidx.credentials.TYPE_RESTORE_CREDENTIAL");
                    Intrinsics.checkNotNullParameter(jsonString2, "jsonString");
                    if (jsonString2.length() != 0) {
                        try {
                            new JSONObject(jsonString2);
                            mVar = nVar;
                            dVar.onResult(new p(mVar));
                            return;
                        } catch (Exception unused4) {
                        }
                    }
                    throw new IllegalArgumentException("authenticationResponseJson must not be empty, and must be a valid JSON");
                }
                throw new FrameworkClassParsingException();
            case -543568185:
                if (type.equals("android.credentials.TYPE_PASSWORD_CREDENTIAL")) {
                    Intrinsics.checkNotNullParameter(data, "data");
                    try {
                        String string = data.getString("androidx.credentials.BUNDLE_KEY_ID");
                        String string2 = data.getString("androidx.credentials.BUNDLE_KEY_PASSWORD");
                        Intrinsics.d(string);
                        Intrinsics.d(string2);
                        nVar = new n(1, data, string2);
                        mVar = nVar;
                        dVar.onResult(new p(mVar));
                        return;
                    } catch (Exception unused5) {
                        throw new FrameworkClassParsingException();
                    }
                }
                throw new FrameworkClassParsingException();
            case -95037569:
                if (type.equals("androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL")) {
                    Intrinsics.checkNotNullParameter(data, "data");
                    try {
                        String string3 = data.getString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON");
                        Intrinsics.d(string3);
                        mVar = new n(2, data, string3);
                        dVar.onResult(new p(mVar));
                        return;
                    } catch (Exception unused6) {
                        throw new FrameworkClassParsingException();
                    }
                }
                throw new FrameworkClassParsingException();
            default:
                throw new FrameworkClassParsingException();
        }
    }
}
