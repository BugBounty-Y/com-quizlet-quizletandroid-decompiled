package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class z {
    public final Context a;
    public final String b;
    public final String c;
    public final SharedPreferences d;

    public z(Context context, String str, String str2) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
        this.b = str;
        this.c = str2;
        this.d = assistantMode.refactored.a.g(0, context, "com.braze.storage.sdk_auth_cache", str, str2);
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Setting signature to: ", str);
    }

    public final void b(String str) {
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new D(str, 16), 6, (Object) null);
        this.d.edit().putString("auth_signature", str).apply();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof z)) {
            return false;
        }
        z zVar = (z) obj;
        return Intrinsics.b(this.a, zVar.a) && Intrinsics.b(this.b, zVar.b) && Intrinsics.b(this.c, zVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SdkAuthenticationCache(context=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", apiKey=");
        return androidx.compose.animation.d0.r(sb, this.c, ')');
    }
}
