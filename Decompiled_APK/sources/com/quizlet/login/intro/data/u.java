package com.quizlet.login.intro.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u {
    public final String a;
    public final boolean b;
    public final com.quizlet.features.infra.compatibility.a c;
    public final com.quizlet.login.authentication.k d;
    public final boolean e;

    public u(String str, boolean z, com.quizlet.features.infra.compatibility.a aVar, com.quizlet.login.authentication.k kVar, boolean z2) {
        this.a = str;
        this.b = z;
        this.c = aVar;
        this.d = kVar;
        this.e = z2;
    }

    public static u a(u uVar, com.quizlet.features.infra.compatibility.a aVar, com.quizlet.login.authentication.k kVar, boolean z, int i) {
        String str = (i & 1) != 0 ? uVar.a : null;
        boolean z2 = (i & 2) != 0 ? uVar.b : true;
        if ((i & 4) != 0) {
            aVar = uVar.c;
        }
        com.quizlet.features.infra.compatibility.a aVar2 = aVar;
        if ((i & 8) != 0) {
            kVar = uVar.d;
        }
        com.quizlet.login.authentication.k kVar2 = kVar;
        if ((i & 16) != 0) {
            z = uVar.e;
        }
        uVar.getClass();
        return new u(str, z2, aVar2, kVar2, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return Intrinsics.b(this.a, uVar.a) && this.b == uVar.b && Intrinsics.b(this.c, uVar.c) && Intrinsics.b(this.d, uVar.d) && this.e == uVar.e;
    }

    public final int hashCode() {
        String str = this.a;
        int iG = d0.g((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
        com.quizlet.features.infra.compatibility.a aVar = this.c;
        int iHashCode = (iG + (aVar == null ? 0 : aVar.hashCode())) * 31;
        com.quizlet.login.authentication.k kVar = this.d;
        return Boolean.hashCode(this.e) + ((iHashCode + (kVar != null ? kVar.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IntroUiState(hostOverride=");
        sb.append(this.a);
        sb.append(", shouldKillApp=");
        sb.append(this.b);
        sb.append(", compatibilityCheckMessage=");
        sb.append(this.c);
        sb.append(", authenticationError=");
        sb.append(this.d);
        sb.append(", isLoading=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
