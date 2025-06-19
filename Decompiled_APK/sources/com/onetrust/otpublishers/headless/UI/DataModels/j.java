package com.onetrust.otpublishers.headless.UI.DataModels;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j {
    public final String a;
    public final String b;
    public k c;

    public j(String id, String name, k consentState) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(consentState, "consentState");
        this.a = id;
        this.b = name;
        this.c = consentState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b) && this.c == jVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "VendorItem(id=" + this.a + ", name=" + this.b + ", consentState=" + this.c + ')';
    }
}
