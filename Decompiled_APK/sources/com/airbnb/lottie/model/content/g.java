package com.airbnb.lottie.model.content;

import com.airbnb.lottie.u;
import com.airbnb.lottie.v;
import java.util.HashSet;

/* loaded from: classes.dex */
public final class g implements b {
    public final int a;
    public final boolean b;

    public g(String str, int i, boolean z) {
        this.a = i;
        this.b = z;
    }

    @Override // com.airbnb.lottie.model.content.b
    public final com.airbnb.lottie.animation.content.c a(u uVar, com.airbnb.lottie.h hVar, com.airbnb.lottie.model.layer.b bVar) {
        if (((HashSet) uVar.l.b).contains(v.a)) {
            return new com.airbnb.lottie.animation.content.l(this);
        }
        com.airbnb.lottie.utils.c.b("Animation contains merge paths but they are disabled.");
        return null;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MergePaths{mode=");
        int i = this.a;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "EXCLUDE_INTERSECTIONS" : "INTERSECT" : "SUBTRACT" : "ADD" : "MERGE");
        sb.append('}');
        return sb.toString();
    }
}
