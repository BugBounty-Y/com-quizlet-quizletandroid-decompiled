package com.quizlet.quizletandroid.ui.setcreation.activities;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n {
    public final String a;
    public final com.quizlet.quizletandroid.util.j b;
    public final boolean c;

    public n(String permissionName, com.quizlet.quizletandroid.util.j permissionAccess, boolean z) {
        Intrinsics.checkNotNullParameter(permissionName, "permissionName");
        Intrinsics.checkNotNullParameter(permissionAccess, "permissionAccess");
        this.a = permissionName;
        this.b = permissionAccess;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && this.b == nVar.b && this.c == nVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Permission(permissionName=");
        sb.append(this.a);
        sb.append(", permissionAccess=");
        sb.append(this.b);
        sb.append(", isSelected=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
