package com.quizlet.features.folders.viewmodel.usecases;

import androidx.compose.animation.d0;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final long a;
    public final String b;
    public final long c;
    public final String d;
    public final String e;
    public final LinkedHashSet f;

    public c(long j, String str, long j2, String str2, String folderTitle, LinkedHashSet currentTags) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        Intrinsics.checkNotNullParameter(currentTags, "currentTags");
        this.a = j;
        this.b = str;
        this.c = j2;
        this.d = str2;
        this.e = folderTitle;
        this.f = currentTags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c && Intrinsics.b(this.d, cVar.d) && Intrinsics.b(this.e, cVar.e) && this.f.equals(cVar.f);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iG = d0.g(d0.d((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, false);
        String str2 = this.d;
        return this.f.hashCode() + d0.e((iG + (str2 != null ? str2.hashCode() : 0)) * 31, 31, this.e);
    }

    public final String toString() {
        return "FolderMenuLoadData(folderId=" + this.a + ", folderCreatorName=" + this.b + ", creatorId=" + this.c + ", creatorUnderAge=false, webUrl=" + this.d + ", folderTitle=" + this.e + ", currentTags=" + this.f + ")";
    }
}
