package com.quizlet.shared.models.api.notes;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends h {
    public final String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(String uuid) {
        super(uuid);
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        this.c = uuid;
    }

    @Override // com.quizlet.shared.models.api.notes.h
    public final String a() {
        return this.c;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.c, ((f) obj).c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ByUuid(uuid="), this.c, ")");
    }
}
