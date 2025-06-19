package com.quizlet.features.settings.data.interactor.exceptions;

import com.quizlet.api.model.ServerProvidedError;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements ServerProvidedError {
    public final String a;
    public final String b;

    public a(String str, String str2) {
        this.a = str;
        this.b = str2;
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

    @Override // com.quizlet.api.model.ServerProvidedError
    public final String getIdentifier() {
        return this.a;
    }

    @Override // com.quizlet.api.model.ServerProvidedError
    public final String getServerMessage() {
        return this.b;
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("HttpServerProvidedError(identifier=");
        sb.append(this.a);
        sb.append(", serverMessage=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
