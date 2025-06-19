package com.google.firebase.components;

/* loaded from: classes2.dex */
public final class i {
    public final q a;
    public final boolean b;

    public i(q qVar, boolean z) {
        this.a = qVar;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof i) {
            i iVar = (i) obj;
            if (iVar.a.equals(this.a) && iVar.b == this.b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ Boolean.valueOf(this.b).hashCode();
    }
}
