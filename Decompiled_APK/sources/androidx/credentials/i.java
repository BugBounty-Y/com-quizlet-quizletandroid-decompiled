package androidx.credentials;

import android.adservices.measurement.MeasurementManager;
import android.credentials.ClearCredentialStateException;
import android.credentials.CredentialManager;
import android.credentials.CredentialOption;
import android.credentials.GetCredentialException;
import android.credentials.GetCredentialRequest;
import android.credentials.GetCredentialResponse;
import android.os.Bundle;

/* loaded from: classes.dex */
public abstract /* synthetic */ class i {
    public static /* synthetic */ void C() {
    }

    public static /* synthetic */ void D() {
    }

    public static /* bridge */ /* synthetic */ MeasurementManager k(Object obj) {
        return (MeasurementManager) obj;
    }

    public static /* bridge */ /* synthetic */ ClearCredentialStateException m(Throwable th) {
        return (ClearCredentialStateException) th;
    }

    public static /* bridge */ /* synthetic */ CredentialManager n(Object obj) {
        return (CredentialManager) obj;
    }

    public static /* synthetic */ CredentialOption.Builder p(Bundle bundle, Bundle bundle2) {
        return new CredentialOption.Builder("com.google.android.libraries.identity.googleid.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL", bundle, bundle2);
    }

    public static /* bridge */ /* synthetic */ GetCredentialException q(Throwable th) {
        return (GetCredentialException) th;
    }

    public static /* synthetic */ GetCredentialRequest.Builder r(Bundle bundle) {
        return new GetCredentialRequest.Builder(bundle);
    }

    public static /* bridge */ /* synthetic */ GetCredentialResponse s(Object obj) {
        return (GetCredentialResponse) obj;
    }

    public static /* bridge */ /* synthetic */ Class t() {
        return MeasurementManager.class;
    }

    public static /* synthetic */ void u() {
    }
}
