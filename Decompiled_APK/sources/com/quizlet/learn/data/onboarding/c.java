package com.quizlet.learn.data.onboarding;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final int a;
    public final n b;
    public final v c;
    public final boolean d;

    public c(int i, n nVar, v vVar, boolean z) {
        this.a = i;
        this.b = nVar;
        this.c = vVar;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d;
    }

    public final int hashCode() {
        int iHashCode = Integer.hashCode(this.a) * 31;
        n nVar = this.b;
        int iHashCode2 = (iHashCode + (nVar == null ? 0 : nVar.hashCode())) * 31;
        v vVar = this.c;
        return Boolean.hashCode(this.d) + ((iHashCode2 + (vVar != null ? vVar.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SimplerContent(headerStringRes=");
        sb.append(this.a);
        sb.append(", goalState=");
        sb.append(this.b);
        sb.append(", knowledgeState=");
        sb.append(this.c);
        sb.append(", shouldShowWriteMode=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
