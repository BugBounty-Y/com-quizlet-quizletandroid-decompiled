package androidx.credentials;

import android.os.Bundle;
import androidx.appcompat.app.y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class m extends y {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(Bundle data, String type) {
        super(data, type);
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(data, "data");
        if (type.length() <= 0) {
            throw new IllegalArgumentException("type should not be empty");
        }
    }
}
