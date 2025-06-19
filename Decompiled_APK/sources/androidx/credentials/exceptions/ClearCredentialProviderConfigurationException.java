package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ClearCredentialProviderConfigurationException extends ClearCredentialException {
    public ClearCredentialProviderConfigurationException() {
        this(null);
    }

    public ClearCredentialProviderConfigurationException(String str) {
        super("androidx.credentials.TYPE_CLEAR_CREDENTIAL_PROVIDER_CONFIGURATION_EXCEPTION", str);
    }
}
