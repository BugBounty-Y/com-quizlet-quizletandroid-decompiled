package com.facebook.appevents;

import com.facebook.internal.J;
import java.io.ObjectStreamException;
import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements Serializable {
    public final String a;
    public final String b;

    public b(String str, String applicationId) {
        Intrinsics.checkNotNullParameter(applicationId, "applicationId");
        this.a = applicationId;
        this.b = J.D(str) ? null : str;
    }

    private final Object writeReplace() throws ObjectStreamException {
        return new a(this.b, this.a);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            b bVar = (b) obj;
            String str = bVar.b;
            String str2 = this.b;
            if ((str == null ? str2 == null : str.equals(str2)) && bVar.a.equals(this.a)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.b;
        return (str != null ? str.hashCode() : 0) ^ this.a.hashCode();
    }
}
