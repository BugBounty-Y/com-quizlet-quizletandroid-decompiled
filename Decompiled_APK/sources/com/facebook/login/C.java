package com.facebook.login;

import com.facebook.AccessToken;
import com.facebook.AuthenticationToken;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C {
    public final AccessToken a;
    public final AuthenticationToken b;
    public final LinkedHashSet c;
    public final LinkedHashSet d;

    public C(AccessToken accessToken, AuthenticationToken authenticationToken, LinkedHashSet recentlyGrantedPermissions, LinkedHashSet recentlyDeniedPermissions) {
        Intrinsics.checkNotNullParameter(accessToken, "accessToken");
        Intrinsics.checkNotNullParameter(recentlyGrantedPermissions, "recentlyGrantedPermissions");
        Intrinsics.checkNotNullParameter(recentlyDeniedPermissions, "recentlyDeniedPermissions");
        this.a = accessToken;
        this.b = authenticationToken;
        this.c = recentlyGrantedPermissions;
        this.d = recentlyDeniedPermissions;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C)) {
            return false;
        }
        C c = (C) obj;
        return this.a.equals(c.a) && Intrinsics.b(this.b, c.b) && this.c.equals(c.c) && this.d.equals(c.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        AuthenticationToken authenticationToken = this.b;
        return this.d.hashCode() + ((this.c.hashCode() + ((iHashCode + (authenticationToken == null ? 0 : authenticationToken.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        return "LoginResult(accessToken=" + this.a + ", authenticationToken=" + this.b + ", recentlyGrantedPermissions=" + this.c + ", recentlyDeniedPermissions=" + this.d + ')';
    }
}
