package androidx.credentials.exceptions;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ClearCredentialUnknownException extends ClearCredentialException {
    public ClearCredentialUnknownException() {
        this(null);
    }

    public ClearCredentialUnknownException(String str) {
        super("android.credentials.ClearCredentialStateException.TYPE_UNKNOWN", str);
    }
}
