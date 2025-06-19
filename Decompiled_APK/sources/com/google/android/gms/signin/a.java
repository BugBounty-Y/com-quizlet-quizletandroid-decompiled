package com.google.android.gms.signin;

import com.google.android.gms.common.internal.u;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class a implements com.google.android.gms.common.api.b {
    public static final a a = new a();

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        ((a) obj).getClass();
        return u.l(null, null) && u.l(null, null) && u.l(null, null) && u.l(null, null) && u.l(null, null);
    }

    public final int hashCode() {
        Boolean bool = Boolean.FALSE;
        return Arrays.hashCode(new Object[]{bool, bool, null, bool, bool, null, null, null, null});
    }
}
