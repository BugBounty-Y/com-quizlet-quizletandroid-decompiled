package androidx.credentials.exceptions.domerrors;

import com.comscore.streaming.EventType;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final String a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(int i) {
        this("androidx.credentials.TYPE_ABORT_ERROR");
        switch (i) {
            case 1:
                this("androidx.credentials.TYPE_CONSTRAINT_ERROR");
                break;
            case 3:
                this("androidx.credentials.TYPE_DATA_ERROR");
                break;
            case 4:
                this("androidx.credentials.TYPE_ENCODING_ERROR");
                break;
            case 10:
                this("androidx.credentials.TYPE_INVALID_STATE_ERROR");
                break;
            case 12:
                this("androidx.credentials.TYPE_NETWORK_ERROR");
                break;
            case 14:
                this("androidx.credentials.TYPE_NOT_ALLOWED_ERROR");
                break;
            case 16:
                this("androidx.credentials.TYPE_NOT_READABLE_ERROR");
                break;
            case 17:
                this("androidx.credentials.TYPE_NOT_SUPPORTED_ERROR");
                break;
            case EventType.WINDOW_STATE /* 22 */:
                this("androidx.credentials.TYPE_SECURITY_ERROR");
                break;
            case EventType.VIDEO /* 24 */:
                this("androidx.credentials.TYPE_TIMEOUT_ERROR");
                break;
            case EventType.CDN /* 26 */:
                this("androidx.credentials.TYPE_UNKNOWN_ERROR");
                break;
            default:
                break;
        }
    }

    public a(String type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = type;
    }
}
