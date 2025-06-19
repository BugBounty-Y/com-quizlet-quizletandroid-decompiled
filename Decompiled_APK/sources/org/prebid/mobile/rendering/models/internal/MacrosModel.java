package org.prebid.mobile.rendering.models.internal;

/* loaded from: classes3.dex */
public class MacrosModel {
    public final String a;

    public MacrosModel(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            String str = ((MacrosModel) obj).a;
            String str2 = this.a;
            if (str2 != null) {
                return str2.equals(str);
            }
            if (str == null) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.a;
        if (str != null) {
            return str.hashCode();
        }
        return 0;
    }
}
