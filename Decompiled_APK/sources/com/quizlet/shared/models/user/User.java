package com.quizlet.shared.models.user;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import com.quizlet.shared.enums.j;
import com.quizlet.shared.enums.u;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class User extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] p = {null, null, null, null, null, u.Companion.serializer(), j.Companion.serializer(), null, null, null, null, null, null, null};
    public final long b;
    public final String c;
    public final long d;
    public final long e;
    public final boolean f;
    public final u g;
    public final j h;
    public final boolean i;
    public final String j;
    public final String k;
    public final String l;
    public final boolean m;
    public final int n;
    public final int o;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return User$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ User(int i, long j, String str, long j2, long j3, boolean z, u uVar, j jVar, boolean z2, String str2, String str3, String str4, boolean z3, int i2, int i3) {
        if (16383 != (i & 16383)) {
            AbstractC5047c0.k(i, 16383, User$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = str;
        this.d = j2;
        this.e = j3;
        this.f = z;
        this.g = uVar;
        this.h = jVar;
        this.i = z2;
        this.j = str2;
        this.k = str3;
        this.l = str4;
        this.m = z3;
        this.n = i2;
        this.o = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof User)) {
            return false;
        }
        User user = (User) obj;
        return this.b == user.b && Intrinsics.b(this.c, user.c) && this.d == user.d && this.e == user.e && this.f == user.f && this.g == user.g && this.h == user.h && this.i == user.i && Intrinsics.b(this.j, user.j) && Intrinsics.b(this.k, user.k) && Intrinsics.b(this.l, user.l) && this.m == user.m && this.n == user.n && this.o == user.o;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.g((this.h.hashCode() + ((this.g.hashCode() + d0.g(d0.d(d0.d(d0.e(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e), 31, this.f)) * 31)) * 31, 31, this.i), 31, this.j), 31, this.k);
        String str = this.l;
        return Integer.hashCode(this.o) + d0.b(this.n, d0.g((iE + (str == null ? 0 : str.hashCode())) * 31, 31, this.m), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("User(id=");
        sb.append(this.b);
        sb.append(", username=");
        sb.append(this.c);
        sb.append(", timestamp=");
        sb.append(this.d);
        sb.append(", lastModified=");
        sb.append(this.e);
        sb.append(", isVerified=");
        sb.append(this.f);
        sb.append(", upgradeType=");
        sb.append(this.g);
        sb.append(", selfIdentifiedTeacherStatus=");
        sb.append(this.h);
        sb.append(", isLocked=");
        sb.append(this.i);
        sb.append(", imageURL=");
        sb.append(this.j);
        sb.append(", timeZone=");
        sb.append(this.k);
        sb.append(", profileImageId=");
        sb.append(this.l);
        sb.append(", isDeleted=");
        sb.append(this.m);
        sb.append(", numCreatedSets=");
        sb.append(this.n);
        sb.append(", numClassMemberships=");
        return a.r(sb, this.o, ")");
    }
}
