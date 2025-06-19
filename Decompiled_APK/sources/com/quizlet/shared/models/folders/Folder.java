package com.quizlet.shared.models.folders;

import androidx.compose.animation.d0;
import com.quizlet.shared.models.user.User;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class Folder extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long c;
    public final User d;
    public final String e;
    public final String f;
    public final long g;
    public final long h;
    public final long i;
    public final boolean j;
    public final String k;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Folder$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Folder(int i, long j, User user, String str, String str2, long j2, long j3, long j4, boolean z, String str3) {
        if (511 != (i & 511)) {
            AbstractC5047c0.k(i, 511, Folder$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = j;
        this.d = user;
        this.e = str;
        this.f = str2;
        this.g = j2;
        this.h = j3;
        this.i = j4;
        this.j = z;
        this.k = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Folder)) {
            return false;
        }
        Folder folder = (Folder) obj;
        return this.c == folder.c && Intrinsics.b(this.d, folder.d) && Intrinsics.b(this.e, folder.e) && Intrinsics.b(this.f, folder.f) && this.g == folder.g && this.h == folder.h && this.i == folder.i && this.j == folder.j && Intrinsics.b(this.k, folder.k);
    }

    public final int hashCode() {
        int iG = d0.g(d0.d(d0.d(d0.d(d0.e(d0.e((this.d.hashCode() + (Long.hashCode(this.c) * 31)) * 31, 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i), 31, this.j);
        String str = this.k;
        return iG + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Folder(id=");
        sb.append(this.c);
        sb.append(", user=");
        sb.append(this.d);
        sb.append(", name=");
        sb.append(this.e);
        sb.append(", description=");
        sb.append(this.f);
        sb.append(", timestamp=");
        sb.append(this.g);
        sb.append(", lastModified=");
        sb.append(this.h);
        sb.append(", numSets=");
        sb.append(this.i);
        sb.append(", isHidden=");
        sb.append(this.j);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.k, ")");
    }
}
