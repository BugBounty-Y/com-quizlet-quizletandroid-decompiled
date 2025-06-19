package com.quizlet.features.folders.data;

import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.a0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4271a0 implements InterfaceC4289j0 {
    public final String a;
    public final y1 b;

    public C4271a0(String id, y1 type) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = id;
        this.b = type;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4271a0)) {
            return false;
        }
        C4271a0 c4271a0 = (C4271a0) obj;
        return Intrinsics.b(this.a, c4271a0.a) && this.b == c4271a0.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "GoToAddOrRemoveTags(id=" + this.a + ", type=" + this.b + ")";
    }
}
