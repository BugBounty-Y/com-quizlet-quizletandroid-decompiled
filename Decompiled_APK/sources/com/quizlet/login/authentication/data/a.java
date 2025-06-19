package com.quizlet.login.authentication.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends i {
    public final f a;

    public a(f fVar) {
        this.a = fVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        f fVar = this.a;
        if (fVar == null) {
            return 0;
        }
        return fVar.hashCode();
    }

    public final String toString() {
        return "AccountAlreadyExists(existingAccountInfo=" + this.a + ")";
    }
}
