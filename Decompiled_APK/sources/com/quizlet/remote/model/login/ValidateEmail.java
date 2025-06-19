package com.quizlet.remote.model.login;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ValidateEmail {
    public final String a;
    public final boolean b;
    public final String c;
    public final boolean d;
    public final String e;

    public ValidateEmail(@InterfaceC4853h(name = "address") String str, @InterfaceC4853h(name = "isValid") boolean z, @InterfaceC4853h(name = "didYouMean") String str2, @InterfaceC4853h(name = "isDisposable") boolean z2, @InterfaceC4853h(name = "existingAccount") String str3) {
        this.a = str;
        this.b = z;
        this.c = str2;
        this.d = z2;
        this.e = str3;
    }

    @NotNull
    public final ValidateEmail copy(@InterfaceC4853h(name = "address") String str, @InterfaceC4853h(name = "isValid") boolean z, @InterfaceC4853h(name = "didYouMean") String str2, @InterfaceC4853h(name = "isDisposable") boolean z2, @InterfaceC4853h(name = "existingAccount") String str3) {
        return new ValidateEmail(str, z, str2, z2, str3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ValidateEmail)) {
            return false;
        }
        ValidateEmail validateEmail = (ValidateEmail) obj;
        return Intrinsics.b(this.a, validateEmail.a) && this.b == validateEmail.b && Intrinsics.b(this.c, validateEmail.c) && this.d == validateEmail.d && Intrinsics.b(this.e, validateEmail.e);
    }

    public final int hashCode() {
        String str = this.a;
        int iG = d0.g((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
        String str2 = this.c;
        int iG2 = d0.g((iG + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.d);
        String str3 = this.e;
        return iG2 + (str3 != null ? str3.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ValidateEmail(address=");
        sb.append(this.a);
        sb.append(", isValid=");
        sb.append(this.b);
        sb.append(", didYouMean=");
        sb.append(this.c);
        sb.append(", isDisposable=");
        sb.append(this.d);
        sb.append(", existingAccount=");
        return a.t(sb, this.e, ")");
    }
}
