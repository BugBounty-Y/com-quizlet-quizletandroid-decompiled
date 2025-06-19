package androidx.credentials.exceptions;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public abstract class ClearCredentialException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ClearCredentialException(String type, String str) {
        super(str != null ? str.toString() : null);
        Intrinsics.checkNotNullParameter(type, "type");
    }
}
