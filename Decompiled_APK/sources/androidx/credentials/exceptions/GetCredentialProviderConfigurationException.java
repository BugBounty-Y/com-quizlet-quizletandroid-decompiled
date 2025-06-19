package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class GetCredentialProviderConfigurationException extends GetCredentialException {
    public GetCredentialProviderConfigurationException() {
        this(null);
    }

    public GetCredentialProviderConfigurationException(CharSequence charSequence) {
        super(charSequence, "androidx.credentials.TYPE_GET_CREDENTIAL_PROVIDER_CONFIGURATION_EXCEPTION");
    }
}
