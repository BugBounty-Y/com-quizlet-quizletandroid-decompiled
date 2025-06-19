package androidx.credentials.exceptions.publickeycredential;

import androidx.credentials.exceptions.domerrors.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class GetPublicKeyCredentialDomException extends GetPublicKeyCredentialException {
    public static final /* synthetic */ int b = 0;

    /* JADX WARN: Illegal instructions before constructor call */
    public GetPublicKeyCredentialDomException(a domError, String str) {
        Intrinsics.checkNotNullParameter(domError, "domError");
        String type = "androidx.credentials.TYPE_GET_PUBLIC_KEY_CREDENTIAL_DOM_EXCEPTION/".concat(domError.a);
        Intrinsics.checkNotNullParameter(type, "type");
        super(str, type);
        if (type.length() <= 0) {
            throw new IllegalArgumentException("type must not be empty");
        }
    }
}
