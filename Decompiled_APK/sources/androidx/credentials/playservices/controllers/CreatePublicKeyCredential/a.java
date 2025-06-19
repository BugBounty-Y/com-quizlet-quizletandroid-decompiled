package androidx.credentials.playservices.controllers.CreatePublicKeyCredential;

import com.google.android.gms.fido.fido2.api.common.ErrorCode;
import java.util.LinkedHashMap;
import kotlin.Pair;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public static final LinkedHashMap a;

    static {
        Pair[] pairs = {new Pair(ErrorCode.UNKNOWN_ERR, new androidx.credentials.exceptions.domerrors.a(26)), new Pair(ErrorCode.ABORT_ERR, new androidx.credentials.exceptions.domerrors.a(0)), new Pair(ErrorCode.ATTESTATION_NOT_PRIVATE_ERR, new androidx.credentials.exceptions.domerrors.a(16)), new Pair(ErrorCode.CONSTRAINT_ERR, new androidx.credentials.exceptions.domerrors.a(1)), new Pair(ErrorCode.DATA_ERR, new androidx.credentials.exceptions.domerrors.a(3)), new Pair(ErrorCode.INVALID_STATE_ERR, new androidx.credentials.exceptions.domerrors.a(10)), new Pair(ErrorCode.ENCODING_ERR, new androidx.credentials.exceptions.domerrors.a(4)), new Pair(ErrorCode.NETWORK_ERR, new androidx.credentials.exceptions.domerrors.a(12)), new Pair(ErrorCode.NOT_ALLOWED_ERR, new androidx.credentials.exceptions.domerrors.a(14)), new Pair(ErrorCode.NOT_SUPPORTED_ERR, new androidx.credentials.exceptions.domerrors.a(17)), new Pair(ErrorCode.SECURITY_ERR, new androidx.credentials.exceptions.domerrors.a(22)), new Pair(ErrorCode.TIMEOUT_ERR, new androidx.credentials.exceptions.domerrors.a(24))};
        Intrinsics.checkNotNullParameter(pairs, "pairs");
        LinkedHashMap destination = new LinkedHashMap(U.a(12));
        Intrinsics.checkNotNullParameter(pairs, "<this>");
        Intrinsics.checkNotNullParameter(destination, "destination");
        V.j(destination, pairs);
        a = destination;
    }
}
