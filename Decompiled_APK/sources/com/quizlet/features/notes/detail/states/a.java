package com.quizlet.features.notes.detail.states;

import com.quizlet.data.model.EssayInfo;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements d {
    public final EssayInfo a;
    public final String b;

    public a(EssayInfo artifact, String str) {
        Intrinsics.checkNotNullParameter(artifact, "artifact");
        this.a = artifact;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Error(artifact=");
        sb.append(this.a);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
