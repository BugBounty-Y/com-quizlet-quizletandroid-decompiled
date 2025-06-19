package com.google.android.gms.internal.measurement;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class C {
    public static final /* synthetic */ int b = 0;
    public final int a;

    public C(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        c.getClass();
        int i = this.a;
        if (i != 0) {
            return i == c.a;
        }
        throw null;
    }

    public final int hashCode() {
        int i = this.a;
        if (i != 0) {
            return ((i ^ (-485106924)) * 583896283) ^ 1;
        }
        throw null;
    }

    public final String toString() {
        int i = this.a;
        return AbstractC0147y.e("FileComplianceOptions{fileOwner=, hasDifferentDmaOwner=false, fileChecks=", i != 1 ? i != 2 ? i != 3 ? i != 4 ? "null" : "NO_CHECKS" : "SKIP_SECURITY_CHECK" : "SKIP_COMPLIANCE_CHECK" : "ALL_CHECKS", ", dataForwardingNotAllowedResolver=null, multipleProductIdGroupsResolver=null, filePurpose=", "READ_AND_WRITE", "}");
    }
}
