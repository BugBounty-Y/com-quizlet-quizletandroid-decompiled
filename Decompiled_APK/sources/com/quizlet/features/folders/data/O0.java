package com.quizlet.features.folders.data;

/* loaded from: classes3.dex */
public final class O0 implements P0 {
    public final boolean a;
    public final boolean b;

    public O0(boolean z, boolean z2) {
        this.a = z;
        this.b = z2;
    }

    @Override // com.quizlet.features.folders.data.P0
    public final kotlinx.collections.immutable.b a() {
        return kotlinx.collections.immutable.implementations.immutableList.g.c;
    }

    @Override // com.quizlet.features.folders.data.P0
    public final boolean b() {
        return this.b;
    }

    @Override // com.quizlet.features.folders.data.P0
    public final boolean c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O0)) {
            return false;
        }
        O0 o0 = (O0) obj;
        return this.a == o0.a && this.b == o0.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Loading(isPullRefreshing=");
        sb.append(this.a);
        sb.append(", showSearchToolbarAction=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
