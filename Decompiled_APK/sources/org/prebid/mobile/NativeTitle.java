package org.prebid.mobile;

/* loaded from: classes3.dex */
public class NativeTitle {
    public final String a;

    public NativeTitle(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return this.a.equals(((NativeTitle) obj).a);
    }
}
