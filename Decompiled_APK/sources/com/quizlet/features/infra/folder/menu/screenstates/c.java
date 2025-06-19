package com.quizlet.features.infra.folder.menu.screenstates;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.collections.immutable.e;

/* loaded from: classes3.dex */
public final class c implements d {
    public final e a;
    public final kotlinx.collections.immutable.c b;
    public final boolean c;

    public c(e items, kotlinx.collections.immutable.c selected, boolean z) {
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(selected, "selected");
        this.a = items;
        this.b = selected;
        this.c = z;
    }

    public static c c(c cVar, kotlinx.collections.immutable.c selected, boolean z) {
        e items = cVar.a;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(selected, "selected");
        return new c(items, selected, z);
    }

    @Override // com.quizlet.features.infra.folder.menu.screenstates.d
    public final kotlinx.collections.immutable.b a() {
        return this.a;
    }

    @Override // com.quizlet.features.infra.folder.menu.screenstates.d
    public final kotlinx.collections.immutable.c b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Loaded(items=");
        sb.append(this.a);
        sb.append(", selected=");
        sb.append(this.b);
        sb.append(", isSaveEnabled=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
